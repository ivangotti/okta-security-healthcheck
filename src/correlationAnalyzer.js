const chalk = require('chalk');

class CorrelationAnalyzer {
  constructor() {
    this.userCorrelations = new Map();
    this.ipCorrelations = new Map();
    this.deviceCorrelations = new Map();
  }

  /**
   * Analyzes all detection/hunt results and correlates events
   * @param {Array} detectionResults - Array of detection/hunt results with events
   * @returns {Object} Correlation analysis results
   */
  analyzeFindings(detectionResults) {
    console.log(chalk.bold.cyan('\n' + '='.repeat(80)));
    console.log(chalk.bold.cyan('Performing Correlation Analysis'));
    console.log(chalk.bold.cyan('='.repeat(80)));
    console.log(chalk.gray('\nAnalyzing events to identify patterns and risk indicators...\n'));

    // Reset correlations
    this.userCorrelations.clear();
    this.ipCorrelations.clear();
    this.deviceCorrelations.clear();

    // Process all findings
    detectionResults.forEach(result => {
      if (!result.events || result.events.length === 0) return;

      result.events.forEach(event => {
        this.correlateByUser(event, result);
        this.correlateByIP(event, result);
        this.correlateByDevice(event, result);
      });
    });

    // Calculate risk scores
    const topRiskUsers = this.calculateTopRiskUsers();
    const topRiskIPs = this.calculateTopRiskIPs();
    const topRiskDevices = this.calculateTopRiskDevices();

    // Display analysis
    this.displayAnalysis(topRiskUsers, topRiskIPs, topRiskDevices);

    return {
      topRiskUsers,
      topRiskIPs,
      topRiskDevices,
      totalCorrelations: {
        users: this.userCorrelations.size,
        ips: this.ipCorrelations.size,
        devices: this.deviceCorrelations.size
      }
    };
  }

  correlateByUser(event, result) {
    const userId = event.actor?.alternateId || event.actor?.displayName;
    if (!userId) return;

    if (!this.userCorrelations.has(userId)) {
      this.userCorrelations.set(userId, {
        userId,
        findings: new Set(),
        events: [],
        ips: new Set(),
        locations: new Set(),
        devices: new Set(),
        eventTypes: new Set()
      });
    }

    const correlation = this.userCorrelations.get(userId);
    correlation.findings.add(result.title);
    correlation.events.push({
      timestamp: event.published,
      finding: result.title,
      findingType: result.sourceType,
      eventType: event.eventType,
      outcome: event.outcome?.result,
      ipAddress: event.client?.ipAddress,
      location: this.getLocation(event),
      device: event.client?.device
    });

    if (event.client?.ipAddress) {
      correlation.ips.add(event.client.ipAddress);
    }
    if (event.client?.geographicalContext) {
      correlation.locations.add(this.getLocation(event));
    }
    if (event.client?.device) {
      correlation.devices.add(event.client.device);
    }
    if (event.eventType) {
      correlation.eventTypes.add(event.eventType);
    }
  }

  correlateByIP(event, result) {
    const ipAddress = event.client?.ipAddress;
    if (!ipAddress) return;

    if (!this.ipCorrelations.has(ipAddress)) {
      this.ipCorrelations.set(ipAddress, {
        ipAddress,
        findings: new Set(),
        events: [],
        users: new Set(),
        locations: new Set()
      });
    }

    const correlation = this.ipCorrelations.get(ipAddress);
    correlation.findings.add(result.title);
    correlation.events.push({
      timestamp: event.published,
      finding: result.title,
      findingType: result.sourceType,
      userId: event.actor?.alternateId,
      outcome: event.outcome?.result
    });

    if (event.actor?.alternateId) {
      correlation.users.add(event.actor.alternateId);
    }
    if (event.client?.geographicalContext) {
      correlation.locations.add(this.getLocation(event));
    }
  }

  correlateByDevice(event, result) {
    const device = event.client?.device;
    if (!device) return;

    const deviceId = device.id || `${device.name}-${device.os_platform}`;
    if (!deviceId) return;

    if (!this.deviceCorrelations.has(deviceId)) {
      this.deviceCorrelations.set(deviceId, {
        deviceId,
        deviceName: device.name,
        platform: device.os_platform,
        findings: new Set(),
        events: [],
        users: new Set()
      });
    }

    const correlation = this.deviceCorrelations.get(deviceId);
    correlation.findings.add(result.title);
    correlation.events.push({
      timestamp: event.published,
      finding: result.title,
      findingType: result.sourceType,
      userId: event.actor?.alternateId
    });

    if (event.actor?.alternateId) {
      correlation.users.add(event.actor.alternateId);
    }
  }

  calculateTopRiskUsers() {
    const users = Array.from(this.userCorrelations.values());

    // Calculate risk score for each user
    users.forEach(user => {
      user.riskScore = this.calculateUserRiskScore(user);
      user.riskLevel = this.getRiskLevel(user.riskScore);
    });

    // Sort by risk score (highest first)
    return users.sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);
  }

  calculateTopRiskIPs() {
    const ips = Array.from(this.ipCorrelations.values());

    ips.forEach(ip => {
      ip.riskScore = this.calculateIPRiskScore(ip);
      ip.riskLevel = this.getRiskLevel(ip.riskScore);
    });

    return ips.sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);
  }

  calculateTopRiskDevices() {
    const devices = Array.from(this.deviceCorrelations.values());

    devices.forEach(device => {
      device.riskScore = this.calculateDeviceRiskScore(device);
      device.riskLevel = this.getRiskLevel(device.riskScore);
    });

    return devices.sort((a, b) => b.riskScore - a.riskScore).slice(0, 5);
  }

  calculateUserRiskScore(user) {
    let score = 0;

    // Number of different findings (weight: 20 points each)
    score += user.findings.size * 20;

    // Total events (weight: 2 points each, capped at 100)
    score += Math.min(user.events.length * 2, 100);

    // Multiple IPs (indicates compromised account or VPN hopping)
    if (user.ips.size > 1) score += user.ips.size * 10;

    // Multiple locations (geographic impossibility)
    if (user.locations.size > 2) score += user.locations.size * 15;

    // Multiple event types (broader attack surface)
    if (user.eventTypes.size > 3) score += user.eventTypes.size * 5;

    // Failed events (weight: 3 points each)
    const failedEvents = user.events.filter(e =>
      e.outcome === 'FAILURE' || e.outcome === 'DENIED' || e.outcome === 'ABANDONED'
    ).length;
    score += failedEvents * 3;

    return score;
  }

  calculateIPRiskScore(ip) {
    let score = 0;

    // Number of different findings
    score += ip.findings.size * 20;

    // Total events
    score += Math.min(ip.events.length * 2, 100);

    // Multiple users from same IP (shared compromised endpoint)
    if (ip.users.size > 1) score += ip.users.size * 25;

    // Multiple locations (proxy/VPN indicator)
    if (ip.locations.size > 1) score += ip.locations.size * 15;

    return score;
  }

  calculateDeviceRiskScore(device) {
    let score = 0;

    score += device.findings.size * 20;
    score += Math.min(device.events.length * 2, 100);

    // Multiple users on same device
    if (device.users.size > 1) score += device.users.size * 30;

    return score;
  }

  getRiskLevel(score) {
    if (score >= 150) return 'CRITICAL';
    if (score >= 100) return 'HIGH';
    if (score >= 50) return 'MODERATE';
    return 'LOW';
  }

  getLocation(event) {
    if (!event.client?.geographicalContext) return null;
    const geo = event.client.geographicalContext;
    return [geo.city, geo.state, geo.country].filter(Boolean).join(', ');
  }

  displayAnalysis(topRiskUsers, topRiskIPs, topRiskDevices) {
    // Top Risk Users
    if (topRiskUsers.length > 0) {
      console.log(chalk.bold.yellow('\n⚠️  TOP RISK USERS\n'));

      topRiskUsers.slice(0, 5).forEach((user, index) => {
        const riskColor = this.getRiskColor(user.riskLevel);
        console.log(chalk.bold.white(`${index + 1}. ${user.userId}`));
        console.log(`   ${riskColor(`Risk Level: ${user.riskLevel}`)} (Score: ${user.riskScore})`);
        console.log(chalk.gray(`   Triggered ${user.findings.size} different finding(s)`));
        console.log(chalk.gray(`   Total Events: ${user.events.length}`));
        console.log(chalk.gray(`   IP Addresses: ${user.ips.size}`));
        console.log(chalk.gray(`   Locations: ${user.locations.size}`));

        // Show top findings for this user
        const findingCounts = this.getTopFindings(user.events, 3);
        if (findingCounts.length > 0) {
          console.log(chalk.cyan('   Top Findings:'));
          findingCounts.forEach(f => {
            console.log(chalk.gray(`     - ${f.finding} (${f.count} event${f.count > 1 ? 's' : ''})`));
          });
        }
        console.log('');
      });
    }

    // Top Risk IPs
    if (topRiskIPs.length > 0) {
      console.log(chalk.bold.yellow('\n⚠️  TOP RISK IP ADDRESSES\n'));

      topRiskIPs.slice(0, 5).forEach((ip, index) => {
        const riskColor = this.getRiskColor(ip.riskLevel);
        console.log(chalk.bold.white(`${index + 1}. ${ip.ipAddress}`));
        console.log(`   ${riskColor(`Risk Level: ${ip.riskLevel}`)} (Score: ${ip.riskScore})`);
        console.log(chalk.gray(`   Triggered ${ip.findings.size} different finding(s)`));
        console.log(chalk.gray(`   Total Events: ${ip.events.length}`));
        console.log(chalk.gray(`   Affected Users: ${ip.users.size}`));

        if (ip.locations.size > 0) {
          const locations = Array.from(ip.locations).slice(0, 2).join('; ');
          console.log(chalk.gray(`   Locations: ${locations}`));
        }
        console.log('');
      });
    }

    // Summary statistics
    console.log(chalk.bold.cyan('\n📊 Correlation Statistics\n'));
    console.log(chalk.white(`Total Unique Users Analyzed: ${this.userCorrelations.size}`));
    console.log(chalk.white(`Total Unique IP Addresses: ${this.ipCorrelations.size}`));
    console.log(chalk.white(`Total Unique Devices: ${this.deviceCorrelations.size}`));

    const criticalUsers = topRiskUsers.filter(u => u.riskLevel === 'CRITICAL').length;
    const highUsers = topRiskUsers.filter(u => u.riskLevel === 'HIGH').length;

    if (criticalUsers > 0) {
      console.log(chalk.red(`\n⚠️  ${criticalUsers} user(s) with CRITICAL risk level - immediate investigation recommended`));
    }
    if (highUsers > 0) {
      console.log(chalk.yellow(`⚠️  ${highUsers} user(s) with HIGH risk level - review recommended`));
    }

    console.log(chalk.cyan('\n' + '='.repeat(80) + '\n'));
  }

  getTopFindings(events, limit) {
    const findingCounts = {};
    events.forEach(event => {
      findingCounts[event.finding] = (findingCounts[event.finding] || 0) + 1;
    });

    return Object.entries(findingCounts)
      .map(([finding, count]) => ({ finding, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  getRiskColor(level) {
    switch (level) {
      case 'CRITICAL': return chalk.red.bold;
      case 'HIGH': return chalk.red;
      case 'MODERATE': return chalk.yellow;
      case 'LOW': return chalk.green;
      default: return chalk.gray;
    }
  }
}

module.exports = CorrelationAnalyzer;
