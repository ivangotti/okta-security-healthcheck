const blessed = require('blessed');
const chalk = require('chalk');

class TerminalGui {
  constructor() {
    this.screen = null;
    this.header = null;
    this.logBox = null;
    this.mascotBox = null;
    this.mascotFrame = 0;
    this.mascotInterval = null;
    this.headerInterval = null;
    this.isInitialized = false;
    this.oktaDomain = null;
  }

  initialize(config = null) {
    if (this.isInitialized) return;

    // Store Okta domain if provided
    if (config && config.okta && config.okta.domain) {
      this.oktaDomain = config.okta.domain;
    }

    // Create screen
    this.screen = blessed.screen({
      smartCSR: true,
      fullUnicode: true,
      title: 'Okta Security Healthcheck'
    });

    // Create header box with border (height 6 to fit content + owl)
    this.header = blessed.box({
      top: 0,
      left: 0,
      width: '100%',
      height: 6,
      tags: true,
      border: {
        type: 'line',
        fg: 'cyan'
      },
      style: {
        fg: 'white'
      }
    });

    // Create mascot animation box (inside header, top right)
    this.mascotBox = blessed.box({
      parent: this.header,
      top: 0,
      right: 1,
      width: 9,
      height: 3,
      tags: true,
      style: {
        fg: 'green'
      }
    });

    // Create scrolling log area with border
    this.logBox = blessed.log({
      top: 6,
      left: 0,
      width: '100%',
      height: '100%-6',
      tags: true,
      border: {
        type: 'line',
        fg: 'cyan'
      },
      scrollable: true,
      alwaysScroll: true,
      scrollbar: {
        ch: '█',
        fg: 'cyan'
      },
      mouse: true,
      keys: true,
      vi: true,
      style: {
        fg: 'white'
      }
    });

    // Add components to screen (mascot is already child of header)
    this.screen.append(this.header);
    this.screen.append(this.logBox);

    // Update header with title and time
    this.updateHeader();

    // Update header time every second
    this.headerInterval = setInterval(() => {
      this.updateHeader();
      this.screen.render();
    }, 1000);

    // Start mascot animation
    this.startMascotAnimation();

    // Handle exit
    this.screen.key(['escape', 'q', 'C-c'], () => {
      this.cleanup();
      process.exit(0);
    });

    // Focus on log box for scrolling
    this.logBox.focus();

    // Initial render
    this.screen.render();

    this.isInitialized = true;
  }

  updateHeader() {
    const now = new Date();
    const dateStr = now.toISOString().split('T')[0];
    const timeStr = now.toTimeString().split(' ')[0];

    let headerText = `{bold}{cyan-fg}🔒 Okta Security Healthcheck{/cyan-fg}{/bold} {yellow-fg}by Ivan Gotti{/yellow-fg}\n` +
                     `{gray-fg}📅 ${dateStr} ⏰ ${timeStr}{/gray-fg}`;

    // Add Okta org URL if available
    if (this.oktaDomain) {
      headerText += `\n{white-fg}🌐 Scanning:{/white-fg} {green-fg}${this.oktaDomain}{/green-fg}`;
    }

    this.header.setContent(headerText);
  }

  startMascotAnimation() {
    // Cute owl mascot animation frames with different expressions
    const frames = [
      // Frame 0 - normal
      `{cyan-fg}  ,___,
 [o.o]
  )::({/cyan-fg}`,
      // Frame 1 - happy
      `{cyan-fg}  ,___,
 [^.^]
  )::({/cyan-fg}`,
      // Frame 2 - vigilant
      `{cyan-fg}  ,___,
 [O.O]
  )::({/cyan-fg}`,
      // Frame 3 - wink
      `{cyan-fg}  ,___,
 [-.o]
  )::({/cyan-fg}`,
      // Frame 4 - alert
      `{cyan-fg}  ,___,
 [@.@]
  )::({/cyan-fg}`,
      // Frame 5 - sleepy
      `{cyan-fg}  ,___,
 [-.-]
  )::({/cyan-fg}`,
      // Frame 6 - excited
      `{cyan-fg}  ,___,
 [*.*]
  )::({/cyan-fg}`,
      // Frame 7 - watching
      `{cyan-fg}  ,___,
 [o.o]
  )::({/cyan-fg}`
    ];

    this.mascotInterval = setInterval(() => {
      this.mascotBox.setContent(frames[this.mascotFrame]);
      this.mascotFrame = (this.mascotFrame + 1) % frames.length;
      this.screen.render();
    }, 500); // Change frame every 500ms
  }

  log(message, style = '') {
    if (!this.isInitialized) {
      console.log(message);
      return;
    }

    // Strip chalk colors and convert to blessed tags
    let formattedMessage = this.convertChalkToBlessedTags(message);

    // Add line to scrolling log
    this.logBox.pushLine(formattedMessage);
    this.screen.render();
  }

  convertChalkToBlessedTags(text) {
    // Remove ANSI codes
    text = text.replace(/\x1b\[[0-9;]*m/g, '');

    // Return as-is, blessed will handle it
    return text;
  }

  // Colored logging helpers
  success(message) {
    this.log(`{green-fg}✓ ${message}{/green-fg}`);
  }

  error(message) {
    this.log(`{red-fg}✗ ${message}{/red-fg}`);
  }

  warning(message) {
    this.log(`{yellow-fg}⚠ ${message}{/yellow-fg}`);
  }

  info(message) {
    this.log(`{cyan-fg}ℹ ${message}{/cyan-fg}`);
  }

  section(title) {
    const separator = '═'.repeat(76);
    this.log(`\n{bold}{cyan-fg}${separator}{/cyan-fg}{/bold}`);
    this.log(`{bold}{cyan-fg}${title}{/cyan-fg}{/bold}`);
    this.log(`{bold}{cyan-fg}${separator}{/cyan-fg}{/bold}\n`);
  }

  detection(index, total, title, type = 'detection') {
    const emoji = type === 'hunt' ? '🔍' : '🛡️';
    const typeLabel = type === 'hunt' ? '{magenta-fg}[HUNT]{/magenta-fg}' : '{cyan-fg}[DETECTION]{/cyan-fg}';
    this.log(`\n{bold}${emoji} [${index}/${total}] ${typeLabel} ${title}{/bold}`);
  }

  finding(count) {
    if (count > 0) {
      this.log(`{bold}{yellow-fg}⚠️  FINDINGS DETECTED: ${count} event(s){/yellow-fg}{/bold}`);
    } else {
      this.log(`{green-fg}✓ No events found - This detection did not trigger{/green-fg}`);
    }
  }

  riskUser(index, userId, riskLevel, score) {
    const emoji = this.getRiskEmoji(riskLevel);
    const color = this.getRiskColor(riskLevel);
    this.log(`\n{bold}${emoji} ${index}. ${userId}{/bold}`);
    this.log(`   {${color}-fg}Risk Level: ${riskLevel}{/${color}-fg} (Score: ${score})`);
  }

  riskIP(index, ip, riskLevel, score) {
    const emoji = this.getRiskEmoji(riskLevel);
    const color = this.getRiskColor(riskLevel);
    this.log(`\n{bold}🌐 ${index}. ${ip}{/bold}`);
    this.log(`   {${color}-fg}Risk Level: ${riskLevel}{/${color}-fg} (Score: ${score})`);
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

  getRiskColor(level) {
    switch (level) {
      case 'CRITICAL': return 'red';
      case 'HIGH': return 'yellow';
      case 'MODERATE': return 'yellow';
      case 'LOW': return 'green';
      default: return 'gray';
    }
  }

  event(index, event) {
    // Event header with index
    this.log(`\n{bold}{yellow-fg}┌─ 📋 Event ${index} ─────────────────────────────────{/yellow-fg}{/bold}`);

    // Format timestamp in a more readable way
    const timestamp = new Date(event.published).toLocaleString('en-US', {
      month: 'short',
      day: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    });
    this.log(`{yellow-fg}│{/yellow-fg} {bold}{white-fg}⏰ Time:{/white-fg}{/bold}       {cyan-fg}${timestamp}{/cyan-fg}`);

    // Event Type with highlighting
    this.log(`{yellow-fg}│{/yellow-fg} {bold}{white-fg}📌 Event Type:{/white-fg}{/bold}  {magenta-fg}${event.eventType}{/magenta-fg}`);

    // Actor with highlighting
    if (event.actor?.alternateId) {
      this.log(`{yellow-fg}│{/yellow-fg} {bold}{white-fg}👤 Actor:{/white-fg}{/bold}      {green-fg}${event.actor.alternateId}{/green-fg}`);
    }

    // Display name if different from alternateId
    if (event.actor?.displayName && event.actor.displayName !== event.actor.alternateId) {
      this.log(`{yellow-fg}│{/yellow-fg}   {gray-fg}Display Name: ${event.actor.displayName}{/gray-fg}`);
    }

    // IP Address with emphasis
    if (event.client?.ipAddress) {
      this.log(`{yellow-fg}│{/yellow-fg} {bold}{white-fg}🌐 IP Address:{/white-fg}{/bold}  {cyan-fg}${event.client.ipAddress}{/cyan-fg}`);
    }

    // User Agent if available
    if (event.client?.userAgent?.rawUserAgent) {
      const ua = event.client.userAgent.rawUserAgent;
      const shortUA = ua.length > 60 ? ua.substring(0, 57) + '...' : ua;
      this.log(`{yellow-fg}│{/yellow-fg}   {gray-fg}🖥️  User Agent: ${shortUA}{/gray-fg}`);
    }

    // Geographic location with flag-like indicator
    if (event.client?.geographicalContext) {
      const geo = event.client.geographicalContext;
      const location = [geo.city, geo.state, geo.country].filter(Boolean).join(', ');
      if (location) {
        this.log(`{yellow-fg}│{/yellow-fg} {bold}{white-fg}📍 Location:{/white-fg}{/bold}   {yellow-fg}${location}{/yellow-fg}`);
      }
    }

    // Device information if available
    if (event.client?.device) {
      this.log(`{yellow-fg}│{/yellow-fg}   {gray-fg}📱 Device: ${event.client.device}{/gray-fg}`);
    }

    // Outcome with contextual emoji and color
    if (event.outcome) {
      let outcomeEmoji = '✓';
      let outcomeColor = 'white';

      if (event.outcome.result === 'SUCCESS') {
        outcomeEmoji = '✅';
        outcomeColor = 'green';
      } else if (event.outcome.result === 'FAILURE') {
        outcomeEmoji = '❌';
        outcomeColor = 'red';
      } else if (event.outcome.result === 'DENY' || event.outcome.result === 'DENIED') {
        outcomeEmoji = '🚫';
        outcomeColor = 'red';
      } else if (event.outcome.result === 'ALLOW') {
        outcomeEmoji = '✅';
        outcomeColor = 'green';
      }

      this.log(`{yellow-fg}│{/yellow-fg} {bold}{white-fg}${outcomeEmoji} Outcome:{/white-fg}{/bold}   {bold}{${outcomeColor}-fg}${event.outcome.result}{/${outcomeColor}-fg}{/bold}`);

      // Reason with better formatting
      if (event.outcome.reason) {
        this.log(`{yellow-fg}│{/yellow-fg}   {gray-fg}💬 Reason: ${event.outcome.reason}{/gray-fg}`);
      }
    }

    // Target information if available
    if (event.target && event.target.length > 0) {
      const target = event.target[0];
      if (target.displayName) {
        this.log(`{yellow-fg}│{/yellow-fg} {bold}{white-fg}🎯 Target:{/white-fg}{/bold}     {cyan-fg}${target.displayName}{/cyan-fg} {gray-fg}(${target.type}){/gray-fg}`);
      }
    }

    // Debug context if available
    if (event.debugContext?.debugData) {
      const debug = event.debugContext.debugData;
      if (debug.requestUri) {
        this.log(`{yellow-fg}│{/yellow-fg}   {gray-fg}🔗 Request: ${debug.requestUri}{/gray-fg}`);
      }
    }

    // Close the event box
    this.log(`{yellow-fg}└───────────────────────────────────────────────────{/yellow-fg}`);
  }

  progress(message) {
    this.log(`{gray-fg}⏳ ${message}...{/gray-fg}`);
  }

  cleanup() {
    if (this.mascotInterval) {
      clearInterval(this.mascotInterval);
    }
    if (this.headerInterval) {
      clearInterval(this.headerInterval);
    }
    if (this.screen) {
      this.screen.destroy();
    }
  }

  render() {
    if (this.screen) {
      this.screen.render();
    }
  }
}

// Create singleton instance
const gui = new TerminalGui();

module.exports = gui;
