const axios = require('axios');
const yaml = require('js-yaml');
const fs = require('fs').promises;
const path = require('path');
const chalk = require('chalk');

class DetectionLoader {
  constructor() {
    this.sources = [
      {
        name: 'detections',
        githubBaseUrl: 'https://api.github.com/repos/okta/customer-detections/contents/detections',
        rawBaseUrl: 'https://raw.githubusercontent.com/okta/customer-detections/master/detections',
        type: 'detection'
      },
      {
        name: 'hunts',
        githubBaseUrl: 'https://api.github.com/repos/okta/customer-detections/contents/hunts',
        rawBaseUrl: 'https://raw.githubusercontent.com/okta/customer-detections/master/hunts',
        type: 'hunt'
      }
    ];
    this.cacheDir = path.join(process.cwd(), 'detections');
  }

  async loadDetections(forceRefresh = true) {
    try {
      // Create cache directory if it doesn't exist
      await fs.mkdir(this.cacheDir, { recursive: true });

      const cacheFile = path.join(this.cacheDir, 'detections.json');

      // Try to load from cache only if explicitly requested (offline mode)
      if (!forceRefresh) {
        try {
          const cached = await fs.readFile(cacheFile, 'utf-8');
          const detections = JSON.parse(cached);
          console.log(chalk.gray(`Loaded ${detections.length} detections and hunts from cache (offline mode)`));
          return detections;
        } catch (err) {
          console.log(chalk.yellow('Cache not found, fetching from GitHub...'));
        }
      }

      console.log(chalk.cyan('Fetching latest detection rules and hunts from GitHub...'));

      const allDetections = [];
      let totalLoadedCount = 0;
      let totalSkippedCount = 0;

      // Load from each source (detections and hunts)
      for (const source of this.sources) {
        console.log(chalk.gray(`  Fetching ${source.name}...`));

        try {
          // Get list of files from this source
          const response = await axios.get(source.githubBaseUrl);
          const files = response.data.filter(file => file.name.endsWith('.yml'));

          let loadedCount = 0;
          let skippedCount = 0;

          for (const file of files) {
            try {
              const yamlResponse = await axios.get(`${source.rawBaseUrl}/${file.name}`);
              const detection = yaml.load(yamlResponse.data);

              // Add metadata for reference
              detection.filename = file.name;
              detection.sourceType = source.type;

              // Check if detection has OIE query - only load OIE detections
              if (detection.detection &&
                  detection.detection.okta_systemlog &&
                  detection.detection.okta_systemlog.OIE) {
                detection.queryType = 'OIE';
                detection.query = detection.detection.okta_systemlog.OIE.trim();
                allDetections.push(detection);
                loadedCount++;
              } else {
                skippedCount++;
              }

              // Small delay to avoid rate limiting
              await this.sleep(100);
            } catch (error) {
              console.warn(chalk.red(`    ✗ Failed to load ${file.name}: ${error.message}`));
            }
          }

          console.log(chalk.green(`    ✓ Loaded ${loadedCount} ${source.name}`));
          if (skippedCount > 0) {
            console.log(chalk.gray(`      (Skipped ${skippedCount} non-OIE ${source.name})`));
          }

          totalLoadedCount += loadedCount;
          totalSkippedCount += skippedCount;
        } catch (error) {
          console.warn(chalk.red(`    ✗ Failed to fetch ${source.name}: ${error.message}`));
        }
      }

      // Save to cache as backup
      await fs.writeFile(cacheFile, JSON.stringify(allDetections, null, 2));

      console.log(chalk.green(`\n✓ Total: ${totalLoadedCount} executable detections and hunts from GitHub`));
      if (totalSkippedCount > 0) {
        console.log(chalk.gray(`  (Skipped ${totalSkippedCount} non-OIE items)\n`));
      } else {
        console.log('');
      }

      return allDetections;
    } catch (error) {
      // If GitHub fetch fails, try to load from cache as fallback
      console.error(chalk.red(`Failed to fetch from GitHub: ${error.message}`));
      console.log(chalk.yellow('Attempting to load from cache...'));

      try {
        const cacheFile = path.join(this.cacheDir, 'detections.json');
        const cached = await fs.readFile(cacheFile, 'utf-8');
        const detections = JSON.parse(cached);
        console.log(chalk.yellow(`⚠ Loaded ${detections.length} detections and hunts from cache (GitHub unavailable)\n`));
        return detections;
      } catch (cacheError) {
        throw new Error(`Failed to load detections and hunts from GitHub and no cache available: ${error.message}`);
      }
    }
  }

  filterExecutableDetections(detections) {
    return detections.filter(d => d.queryType === 'OIE' && d.query);
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = DetectionLoader;
