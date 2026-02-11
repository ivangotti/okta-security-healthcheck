const axios = require('axios');
const yaml = require('js-yaml');
const fs = require('fs').promises;
const path = require('path');
const chalk = require('chalk');

class DetectionLoader {
  constructor() {
    this.githubBaseUrl = 'https://api.github.com/repos/okta/customer-detections/contents/detections';
    this.rawBaseUrl = 'https://raw.githubusercontent.com/okta/customer-detections/master/detections';
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
          console.log(chalk.gray(`Loaded ${detections.length} detections from cache (offline mode)`));
          return detections;
        } catch (err) {
          console.log(chalk.yellow('Cache not found, fetching from GitHub...'));
        }
      }

      console.log(chalk.cyan('Fetching latest detection rules from GitHub...'));

      // Get list of detection files
      const response = await axios.get(this.githubBaseUrl);
      const files = response.data.filter(file => file.name.endsWith('.yml'));

      const detections = [];
      let loadedCount = 0;
      let skippedCount = 0;

      for (const file of files) {
        try {
          const yamlResponse = await axios.get(`${this.rawBaseUrl}/${file.name}`);
          const detection = yaml.load(yamlResponse.data);

          // Add filename for reference
          detection.filename = file.name;

          // Check if detection has OIE query - only load OIE detections
          if (detection.detection &&
              detection.detection.okta_systemlog &&
              detection.detection.okta_systemlog.OIE) {
            detection.queryType = 'OIE';
            detection.query = detection.detection.okta_systemlog.OIE.trim();
            detections.push(detection);
            loadedCount++;
          } else {
            skippedCount++;
          }

          // Small delay to avoid rate limiting
          await this.sleep(100);
        } catch (error) {
          console.warn(chalk.red(`  ✗ Failed to load ${file.name}: ${error.message}`));
        }
      }

      // Save to cache as backup
      await fs.writeFile(cacheFile, JSON.stringify(detections, null, 2));

      console.log(chalk.green(`✓ Loaded ${loadedCount} executable detections from GitHub`));
      console.log(chalk.gray(`  (Skipped ${skippedCount} non-OIE detections)\n`));

      return detections;
    } catch (error) {
      // If GitHub fetch fails, try to load from cache as fallback
      console.error(chalk.red(`Failed to fetch from GitHub: ${error.message}`));
      console.log(chalk.yellow('Attempting to load from cache...'));

      try {
        const cacheFile = path.join(this.cacheDir, 'detections.json');
        const cached = await fs.readFile(cacheFile, 'utf-8');
        const detections = JSON.parse(cached);
        console.log(chalk.yellow(`⚠ Loaded ${detections.length} detections from cache (GitHub unavailable)\n`));
        return detections;
      } catch (cacheError) {
        throw new Error(`Failed to load detections from GitHub and no cache available: ${error.message}`);
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
