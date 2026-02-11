#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');
const chalk = require('chalk');
const OktaClient = require('./oktaClient');
const DetectionLoader = require('./detectionLoader');
const DetectionRunner = require('./detectionRunner');

class SecurityHealthCheck {
  constructor() {
    this.config = null;
    this.oktaClient = null;
    this.detectionLoader = new DetectionLoader();
    this.detectionRunner = null;
  }

  async loadConfig() {
    const configPath = path.join(process.cwd(), 'config.json');

    try {
      const configData = await fs.readFile(configPath, 'utf-8');
      this.config = JSON.parse(configData);

      // Validate required fields
      if (!this.config.okta || !this.config.okta.domain || !this.config.okta.apiToken) {
        throw new Error('Missing required Okta configuration (domain and apiToken)');
      }

      return this.config;
    } catch (error) {
      if (error.code === 'ENOENT') {
        console.error(chalk.red('Error: config.json not found'));
        console.log(chalk.yellow('\nPlease create a config.json file based on config.json.example'));
        console.log(chalk.yellow('Example:'));
        console.log(chalk.gray(`
{
  "okta": {
    "domain": "your-domain.okta.com",
    "apiToken": "your-api-token"
  },
  "query": {
    "since": "2024-01-01T00:00:00Z",
    "limit": 100
  }
}
        `));
        process.exit(1);
      }
      throw error;
    }
  }

  async initialize() {
    console.log(chalk.bold.cyan('\nInitializing Okta Security Health Check...\n'));

    // Load configuration
    await this.loadConfig();
    console.log(chalk.green('✓ Configuration loaded'));

    // Initialize Okta client
    this.oktaClient = new OktaClient(this.config.okta.domain, this.config.okta.apiToken);
    console.log(chalk.green('✓ Okta client initialized'));

    // Test connection
    console.log(chalk.gray('  Testing Okta API connection...'));
    await this.oktaClient.testConnection();
    console.log(chalk.green('✓ Okta API connection successful'));

    // Initialize detection runner
    this.detectionRunner = new DetectionRunner(this.oktaClient, this.config);
    console.log(chalk.green('✓ Detection runner initialized\n'));
  }

  async listDetections(useCache = false) {
    const detections = await this.detectionLoader.loadDetections(!useCache);

    console.log(chalk.bold.cyan('\nAvailable Security Detections:\n'));

    detections.forEach((detection, i) => {
      console.log(chalk.green(`${i + 1}. ${detection.title}`));
      if (detection.description) {
        const shortDesc = detection.description.trim().split('\n')[0];
        console.log(chalk.gray(`   ${shortDesc}`));
      }
      if (detection.threat && detection.threat.Tactic) {
        const tactics = Array.isArray(detection.threat.Tactic)
          ? detection.threat.Tactic.join(', ')
          : detection.threat.Tactic;
        console.log(chalk.yellow(`   Tactic: ${tactics}`));
      }
      console.log('');
    });

    console.log(chalk.white(`Total: ${detections.length} detections\n`));
  }

  async runSpecificDetection(detectionName, useCache = false) {
    const detections = await this.detectionLoader.loadDetections(!useCache);

    // Find detection by title or filename
    const detection = detections.find(d =>
      d.title.toLowerCase().includes(detectionName.toLowerCase()) ||
      d.filename.toLowerCase().includes(detectionName.toLowerCase())
    );

    if (!detection) {
      console.error(chalk.red(`\nError: Detection not found: ${detectionName}`));
      console.log(chalk.yellow('\nUse --list to see all available detections\n'));
      process.exit(1);
    }

    await this.detectionRunner.runDetection(detection, 1, 1);
  }

  async runAllDetections(useCache = false) {
    const detections = await this.detectionLoader.loadDetections(!useCache);
    await this.detectionRunner.runAllDetections(detections);
  }

  parseArguments() {
    const args = process.argv.slice(2);
    const options = {
      list: false,
      detection: null,
      since: null,
      offline: false,
      help: false
    };

    for (let i = 0; i < args.length; i++) {
      const arg = args[i];

      switch (arg) {
        case '--list':
        case '-l':
          options.list = true;
          break;

        case '--detection':
        case '-d':
          options.detection = args[++i];
          break;

        case '--since':
        case '-s':
          options.since = args[++i];
          break;

        case '--offline':
        case '-o':
          options.offline = true;
          break;

        case '--help':
        case '-h':
          options.help = true;
          break;

        default:
          console.error(chalk.red(`Unknown option: ${arg}`));
          options.help = true;
      }
    }

    return options;
  }

  printHelp() {
    console.log(chalk.bold.cyan('\nOkta Security Health Check\n'));
    console.log(chalk.white('Usage: node src/index.js [options]\n'));
    console.log(chalk.white('Options:'));
    console.log(chalk.gray('  --list, -l                List all available detections'));
    console.log(chalk.gray('  --detection, -d <name>    Run a specific detection'));
    console.log(chalk.gray('  --since, -s <date>        Override query start time (ISO 8601 format)'));
    console.log(chalk.gray('  --offline, -o             Use cached detections (skip GitHub fetch)'));
    console.log(chalk.gray('  --help, -h                Show this help message\n'));
    console.log(chalk.white('Note:'));
    console.log(chalk.gray('  By default, the app fetches the latest detection rules from GitHub'));
    console.log(chalk.gray('  to ensure you have the most up-to-date security checks.\n'));
    console.log(chalk.white('Examples:'));
    console.log(chalk.gray('  node src/index.js'));
    console.log(chalk.gray('  node src/index.js --list'));
    console.log(chalk.gray('  node src/index.js --detection "admin console"'));
    console.log(chalk.gray('  node src/index.js --since "2024-02-01T00:00:00Z"'));
    console.log(chalk.gray('  node src/index.js --offline\n'));
  }

  async run() {
    try {
      const options = this.parseArguments();

      if (options.help) {
        this.printHelp();
        return;
      }

      await this.initialize();

      // Override config with command-line options
      if (options.since) {
        if (!this.config.query) {
          this.config.query = {};
        }
        this.config.query.since = options.since;
        console.log(chalk.yellow(`Using custom time range: since ${options.since}\n`));
      }

      if (options.offline) {
        console.log(chalk.yellow('Running in offline mode - using cached detections\n'));
      }

      if (options.list) {
        await this.listDetections(options.offline);
      } else if (options.detection) {
        await this.runSpecificDetection(options.detection, options.offline);
      } else {
        await this.runAllDetections(options.offline);
      }

    } catch (error) {
      console.error(chalk.red(`\nError: ${error.message}`));
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  }
}

// Run the application
const app = new SecurityHealthCheck();
app.run();
