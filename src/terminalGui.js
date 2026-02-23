const ora = require('ora');
const boxen = require('boxen');
const chalk = require('chalk');
const Table = require('cli-table3');

/**
 * Modern terminal UI using industry-standard libraries
 * Patterns based on Vercel, Next.js, Vite, and Prisma CLIs
 */
class TerminalGui {
  constructor() {
    this.isInitialized = false;
    this.oktaDomain = null;
    this.currentSpinner = null;
    this.startTime = null;
  }

  initialize(config = null) {
    if (this.isInitialized) return;

    // Store Okta domain if provided
    if (config && config.okta && config.okta.domain) {
      this.oktaDomain = config.okta.domain;
    }

    this.startTime = Date.now();
    this.isInitialized = true;

    // Show welcome header
    this.showHeader();
  }

  showHeader() {
    const now = new Date();
    const dateStr = now.toISOString().split('T')[0];
    const timeStr = now.toTimeString().split(' ')[0];

    const headerContent = [
      chalk.bold.cyan('🔒 Okta Security Healthcheck') + chalk.yellow(' by Ivan Gotti'),
      chalk.gray(`📅 ${dateStr} ⏰ ${timeStr}`),
      this.oktaDomain ? chalk.white('🌐 Scanning: ') + chalk.green(this.oktaDomain) : ''
    ].filter(Boolean).join('\n');

    console.log(
      boxen(headerContent, {
        padding: 1,
        margin: { top: 1, bottom: 1 },
        borderStyle: 'round',
        borderColor: 'cyan'
      })
    );
  }

  log(message) {
    // Stop current spinner if active
    if (this.currentSpinner && this.currentSpinner.isSpinning) {
      this.currentSpinner.stop();
    }
    console.log(message);
  }

  // Colored logging helpers
  success(message) {
    if (this.currentSpinner && this.currentSpinner.isSpinning) {
      this.currentSpinner.succeed(message);
      this.currentSpinner = null;
    } else {
      console.log(chalk.green('✓') + ' ' + message);
    }
  }

  error(message) {
    if (this.currentSpinner && this.currentSpinner.isSpinning) {
      this.currentSpinner.fail(message);
      this.currentSpinner = null;
    } else {
      console.log(chalk.red('✗') + ' ' + message);
    }
  }

  warning(message) {
    if (this.currentSpinner && this.currentSpinner.isSpinning) {
      this.currentSpinner.warn(message);
      this.currentSpinner = null;
    } else {
      console.log(chalk.yellow('⚠') + ' ' + message);
    }
  }

  info(message) {
    if (this.currentSpinner && this.currentSpinner.isSpinning) {
      this.currentSpinner.info(message);
      this.currentSpinner = null;
    } else {
      console.log(chalk.cyan('ℹ') + ' ' + message);
    }
  }

  section(title) {
    // Stop current spinner if active
    if (this.currentSpinner && this.currentSpinner.isSpinning) {
      this.currentSpinner.stop();
      this.currentSpinner = null;
    }

    console.log('\n' + boxen(chalk.bold.cyan(title), {
      padding: { left: 2, right: 2, top: 0, bottom: 0 },
      margin: { top: 1, bottom: 1 },
      borderStyle: 'round',
      borderColor: 'cyan'
    }));
  }

  detection(index, total, title, type = 'detection') {
    // Stop previous spinner if exists
    if (this.currentSpinner && this.currentSpinner.isSpinning) {
      this.currentSpinner.stop();
    }

    const emoji = type === 'hunt' ? '🔍' : '🛡️';
    const typeLabel = type === 'hunt' ? chalk.magenta('[HUNT]') : chalk.cyan('[DETECTION]');
    const progress = chalk.gray(`[${index}/${total}]`);

    this.currentSpinner = ora({
      text: `${progress} ${typeLabel} ${title}`,
      prefixText: emoji
    }).start();
  }

  finding(count) {
    if (count > 0) {
      if (this.currentSpinner && this.currentSpinner.isSpinning) {
        this.currentSpinner.stopAndPersist({
          symbol: chalk.yellow('⚠️'),
          text: this.currentSpinner.text + chalk.yellow(` → ${count} event(s) found`)
        });
      } else {
        console.log(chalk.yellow('⚠️  FINDINGS DETECTED: ') + chalk.bold(`${count} event(s)`));
      }
    } else {
      if (this.currentSpinner && this.currentSpinner.isSpinning) {
        this.currentSpinner.succeed(this.currentSpinner.text + chalk.gray(' → No events'));
      } else {
        console.log(chalk.green('✓ No events found - This detection did not trigger'));
      }
    }
    this.currentSpinner = null;
  }

  riskUser(index, userId, riskLevel, score) {
    const emoji = this.getRiskEmoji(riskLevel);
    const colorFn = this.getRiskColorFunction(riskLevel);

    console.log(`\n${emoji} ${chalk.bold(index + '. ' + userId)}`);
    console.log(`   ${colorFn('Risk Level: ' + riskLevel)} ${chalk.gray('(Score: ' + score + ')')}`);
  }

  riskIP(index, ip, riskLevel, score) {
    const emoji = this.getRiskEmoji(riskLevel);
    const colorFn = this.getRiskColorFunction(riskLevel);

    console.log(`\n🌐 ${chalk.bold(index + '. ' + ip)}`);
    console.log(`   ${colorFn('Risk Level: ' + riskLevel)} ${chalk.gray('(Score: ' + score + ')')}`);
  }

  getRiskEmoji(level) {
    switch (level) {
      case 'CRITICAL': return '🔴';
      case 'HIGH': return '🟠';
      case 'MODERATE': return '🟡';
      case 'LOW': return '🟢';
      default: return '⚪';
    }
  }

  getRiskColorFunction(level) {
    switch (level) {
      case 'CRITICAL': return chalk.red.bold;
      case 'HIGH': return chalk.yellow.bold;
      case 'MODERATE': return chalk.yellow;
      case 'LOW': return chalk.green;
      default: return chalk.gray;
    }
  }

  event(index, event) {
    console.log(`\n${chalk.yellow.bold('📋 Event ' + index + ':')}`);
    console.log(`  ${chalk.cyan('⏰ Time:')} ${event.published}`);
    console.log(`  ${chalk.cyan('📌 Event Type:')} ${event.eventType}`);

    if (event.actor?.alternateId) {
      console.log(`  ${chalk.cyan('👤 Actor:')} ${event.actor.alternateId}`);
    }

    if (event.client?.ipAddress) {
      console.log(`  ${chalk.cyan('🌐 IP Address:')} ${event.client.ipAddress}`);
    }

    if (event.client?.geographicalContext) {
      const geo = event.client.geographicalContext;
      const location = [geo.city, geo.state, geo.country].filter(Boolean).join(', ');
      if (location) {
        console.log(`  ${chalk.cyan('📍 Location:')} ${location}`);
      }
    }

    if (event.outcome) {
      const outcomeColor = event.outcome.result === 'SUCCESS' ? chalk.green :
                          event.outcome.result === 'FAILURE' ? chalk.red : chalk.white;
      console.log(`  ${chalk.cyan('✓ Outcome:')} ${outcomeColor(event.outcome.result)}`);

      if (event.outcome.reason) {
        console.log(`  ${chalk.cyan('💬 Reason:')} ${event.outcome.reason}`);
      }
    }
  }

  progress(message) {
    // Stop previous spinner if exists
    if (this.currentSpinner && this.currentSpinner.isSpinning) {
      this.currentSpinner.stop();
    }

    this.currentSpinner = ora(message).start();
  }

  /**
   * Display a summary table (modern CLI pattern)
   */
  summaryTable(data) {
    const table = new Table({
      head: [chalk.cyan('Metric'), chalk.cyan('Value')],
      style: {
        head: [],
        border: ['cyan']
      }
    });

    Object.entries(data).forEach(([key, value]) => {
      table.push([key, value]);
    });

    console.log('\n' + table.toString());
  }

  /**
   * Display risk summary as a formatted table
   */
  riskSummaryTable(summary) {
    const table = new Table({
      head: [chalk.cyan('Risk Level'), chalk.cyan('Count'), chalk.cyan('Users')],
      style: {
        head: [],
        border: ['cyan']
      }
    });

    const riskLevels = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'];
    riskLevels.forEach(level => {
      if (summary[level]) {
        const emoji = this.getRiskEmoji(level);
        const colorFn = this.getRiskColorFunction(level);
        table.push([
          `${emoji} ${colorFn(level)}`,
          summary[level].count || 0,
          summary[level].users?.slice(0, 3).join(', ') || 'None'
        ]);
      }
    });

    console.log('\n' + table.toString());
  }

  /**
   * Show elapsed time
   */
  showElapsedTime() {
    if (this.startTime) {
      const elapsed = Math.round((Date.now() - this.startTime) / 1000);
      const minutes = Math.floor(elapsed / 60);
      const seconds = elapsed % 60;
      const timeStr = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
      console.log(chalk.gray(`\n⏱  Completed in ${timeStr}`));
    }
  }

  cleanup() {
    // Stop any active spinner
    if (this.currentSpinner && this.currentSpinner.isSpinning) {
      this.currentSpinner.stop();
    }
    // No screen to destroy in modern approach
  }

  render() {
    // No-op in modern stdout-based approach
    // Kept for API compatibility
  }
}

// Create singleton instance
const gui = new TerminalGui();

module.exports = gui;
