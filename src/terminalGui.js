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

    // Create header box (increased height for mascot and org info)
    this.header = blessed.box({
      top: 0,
      left: 0,
      width: '100%',
      height: 5,
      tags: true,
      border: {
        type: 'line',
        fg: 'cyan'
      },
      style: {
        fg: 'white'
      }
    });

    // Create mascot animation box (top right)
    this.mascotBox = blessed.box({
      top: 1,
      right: 2,
      width: 15,
      height: 3,
      tags: true,
      style: {
        fg: 'green'
      }
    });

    // Create scrolling log box
    this.logBox = blessed.log({
      top: 5,
      left: 0,
      width: '100%',
      height: '100%-5',
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

    // Add all components to screen
    this.screen.append(this.header);
    this.screen.append(this.mascotBox);
    this.screen.append(this.logBox);

    // Update header with title and time
    this.updateHeader();

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

    this.logBox.log(formattedMessage);
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
    this.log(`\n{bold}{yellow-fg}📋 Event ${index}:{/yellow-fg}{/bold}`);
    this.log(`  {cyan-fg}⏰ Time:{/cyan-fg} ${event.published}`);
    this.log(`  {cyan-fg}📌 Event Type:{/cyan-fg} ${event.eventType}`);

    if (event.actor?.alternateId) {
      this.log(`  {cyan-fg}👤 Actor:{/cyan-fg} ${event.actor.alternateId}`);
    }

    if (event.client?.ipAddress) {
      this.log(`  {cyan-fg}🌐 IP Address:{/cyan-fg} ${event.client.ipAddress}`);
    }

    if (event.client?.geographicalContext) {
      const geo = event.client.geographicalContext;
      const location = [geo.city, geo.state, geo.country].filter(Boolean).join(', ');
      if (location) {
        this.log(`  {cyan-fg}📍 Location:{/cyan-fg} ${location}`);
      }
    }

    if (event.outcome) {
      const outcomeColor = event.outcome.result === 'SUCCESS' ? 'green' :
                          event.outcome.result === 'FAILURE' ? 'red' : 'white';
      this.log(`  {cyan-fg}✓ Outcome:{/cyan-fg} {${outcomeColor}-fg}${event.outcome.result}{/${outcomeColor}-fg}`);

      if (event.outcome.reason) {
        this.log(`  {cyan-fg}💬 Reason:{/cyan-fg} ${event.outcome.reason}`);
      }
    }
  }

  progress(message) {
    this.log(`{gray-fg}⏳ ${message}...{/gray-fg}`);
  }

  cleanup() {
    if (this.mascotInterval) {
      clearInterval(this.mascotInterval);
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
