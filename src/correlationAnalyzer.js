const chalk = require('chalk');
const gui = require('./terminalGui');

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
    gui.section('Performing Correlation Analysis');
    gui.log('{gray-fg}🔬 Analyzing events to identify patterns and risk indicators...{/gray-fg}\n');

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
      gui.log('\n{bold}{yellow-fg}👥 TOP RISK USERS (Cross-Detection Analysis){/yellow-fg}{/bold}\n');
      gui.log('{gray-fg}These users triggered multiple security detections/hunts across your environment:{/gray-fg}\n');

      topRiskUsers.slice(0, 5).forEach((user, index) => {
        gui.riskUser(index + 1, user.userId, user.riskLevel, user.riskScore);
        gui.log(`   {gray-fg}📊 Total Events: ${user.events.length}{/gray-fg}`);
        gui.log(`   {gray-fg}🌐 IP Addresses Used: ${user.ips.size}{/gray-fg}`);
        if (user.ips.size > 0) {
          const ipList = Array.from(user.ips).slice(0, 3).join(', ');
          gui.log(`   {gray-fg}   └─ ${ipList}${user.ips.size > 3 ? ` (+${user.ips.size - 3} more)` : ''}{/gray-fg}`);
        }
        gui.log(`   {gray-fg}📍 Geographic Locations: ${user.locations.size}{/gray-fg}`);
        if (user.locations.size > 0) {
          const locationList = Array.from(user.locations).slice(0, 2).join('; ');
          gui.log(`   {gray-fg}   └─ ${locationList}${user.locations.size > 2 ? ' (+ more)' : ''}{/gray-fg}`);
        }

        // Show ALL findings for this user (not just top 3)
        gui.log(`\n   {bold}{cyan-fg}🎯 Found in ${user.findings.size} Detection(s)/Hunt(s):{/cyan-fg}{/bold}`);
        const findingCounts = this.getTopFindings(user.events, 999); // Get all findings
        findingCounts.forEach(f => {
          const typeIcon = this.getTypeIcon(f.type);
          gui.log(`   {yellow-fg}${typeIcon} ${f.finding}{/yellow-fg} {gray-fg}(${f.count} event${f.count > 1 ? 's' : ''}){/gray-fg}`);
        });
        gui.log('');
      });
    }

    // Top Risk IPs
    if (topRiskIPs.length > 0) {
      gui.log('\n{bold}{yellow-fg}🌐 TOP RISK IP ADDRESSES (Cross-User Analysis){/yellow-fg}{/bold}\n');
      gui.log('{gray-fg}These IPs triggered multiple security detections/hunts affecting multiple users:{/gray-fg}\n');

      topRiskIPs.slice(0, 5).forEach((ip, index) => {
        gui.riskIP(index + 1, ip.ipAddress, ip.riskLevel, ip.riskScore);
        gui.log(`   {gray-fg}📊 Total Events: ${ip.events.length}{/gray-fg}`);
        gui.log(`   {gray-fg}👥 Affected Users: ${ip.users.size}{/gray-fg}`);
        if (ip.users.size > 0) {
          const userList = Array.from(ip.users).slice(0, 3).join(', ');
          gui.log(`   {gray-fg}   └─ ${userList}${ip.users.size > 3 ? ` (+${ip.users.size - 3} more)` : ''}{/gray-fg}`);
        }

        if (ip.locations.size > 0) {
          const locations = Array.from(ip.locations).slice(0, 2).join('; ');
          gui.log(`   {gray-fg}📍 Locations: ${locations}${ip.locations.size > 2 ? ' (+ more)' : ''}{/gray-fg}`);
        }

        // Show ALL findings for this IP
        gui.log(`\n   {bold}{cyan-fg}🎯 Found in ${ip.findings.size} Detection(s)/Hunt(s):{/cyan-fg}{/bold}`);
        const findingCounts = this.getIPFindings(ip.events);
        findingCounts.forEach(f => {
          const typeIcon = this.getTypeIcon(f.type);
          gui.log(`   {yellow-fg}${typeIcon} ${f.finding}{/yellow-fg} {gray-fg}(${f.count} event${f.count > 1 ? 's' : ''}){/gray-fg}`);
        });
        gui.log('');
      });
    }

    // Summary statistics
    gui.log('\n{bold}{cyan-fg}📊 Correlation Statistics{/cyan-fg}{/bold}\n');
    gui.log(`{white-fg}👥 Total Unique Users Analyzed: ${this.userCorrelations.size}{/white-fg}`);
    gui.log(`{white-fg}🌐 Total Unique IP Addresses: ${this.ipCorrelations.size}{/white-fg}`);
    gui.log(`{white-fg}💻 Total Unique Devices: ${this.deviceCorrelations.size}{/white-fg}`);

    const criticalUsers = topRiskUsers.filter(u => u.riskLevel === 'CRITICAL').length;
    const highUsers = topRiskUsers.filter(u => u.riskLevel === 'HIGH').length;

    if (criticalUsers > 0) {
      gui.log(`\n{red-fg}🔴 ${criticalUsers} user(s) with CRITICAL risk level - immediate investigation recommended{/red-fg}`);
    }
    if (highUsers > 0) {
      gui.log(`{yellow-fg}🟠 ${highUsers} user(s) with HIGH risk level - review recommended{/yellow-fg}`);
    }

    gui.log('');
  }

  getTopFindings(events, limit) {
    const findingCounts = {};
    events.forEach(event => {
      const key = event.finding;
      if (!findingCounts[key]) {
        findingCounts[key] = {
          finding: event.finding,
          count: 0,
          type: event.findingType
        };
      }
      findingCounts[key].count++;
    });

    return Object.values(findingCounts)
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  getIPFindings(events) {
    const findingCounts = {};
    events.forEach(event => {
      const key = event.finding;
      if (!findingCounts[key]) {
        findingCounts[key] = {
          finding: event.finding,
          count: 0,
          type: event.findingType
        };
      }
      findingCounts[key].count++;
    });

    return Object.values(findingCounts)
      .sort((a, b) => b.count - a.count);
  }

  getTypeIcon(type) {
    return type === 'hunt' ? '🔍' : '🛡️';
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
