const blessed = require('blessed');
const chalk = require('chalk');

class TerminalGui {
  constructor() {
    this.screen = null;
    this.header = null;
    this.logBox = null;
    this.cthulhuBox = null;
    this.cthulhuFrame = 0;
    this.cthulhuInterval = null;
    this.isInitialized = false;
  }

  initialize() {
    if (this.isInitialized) return;

    // Create screen
    this.screen = blessed.screen({
      smartCSR: true,
      fullUnicode: true,
      dockBorders: true,
      title: 'Okta Security Healthcheck'
    });

    // Create header box
    this.header = blessed.box({
      top: 0,
      left: 0,
      width: '100%',
      height: 4,
      tags: true,
      border: {
        type: 'line'
      },
      style: {
        fg: 'white',
        bg: 'blue',
        border: {
          fg: 'cyan'
        }
      }
    });

    // Create Cthulhu animation box (top right)
    this.cthulhuBox = blessed.box({
      top: 1,
      right: 2,
      width: 20,
      height: 2,
      tags: true,
      style: {
        fg: 'green',
        bg: 'blue'
      }
    });

    // Create scrolling log box
    this.logBox = blessed.log({
      top: 4,
      left: 0,
      width: '100%',
      height: '100%-4',
      tags: true,
      border: {
        type: 'line'
      },
      scrollable: true,
      alwaysScroll: true,
      scrollbar: {
        ch: '█',
        style: {
          fg: 'cyan'
        }
      },
      mouse: true,
      keys: true,
      vi: true,
      style: {
        fg: 'white',
        bg: 'black',
        border: {
          fg: 'cyan'
        }
      }
    });

    // Add all components to screen
    this.screen.append(this.header);
    this.screen.append(this.cthulhuBox);
    this.screen.append(this.logBox);

    // Update header with title and time
    this.updateHeader();

    // Start Cthulhu animation
    this.startCthulhuAnimation();

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

    const headerText = `{bold}{cyan-fg}🔒 Okta Security Healthcheck{/cyan-fg}{/bold} {yellow-fg}by Ivan Gotti{/yellow-fg}\n` +
                      `{gray-fg}📅 ${dateStr} ⏰ ${timeStr}{/gray-fg}`;

    this.header.setContent(headerText);
  }

  startCthulhuAnimation() {
    // Cthulhu animation frames
    const frames = [
      // Frame 0 - normal
      `   ⢀⣀⣀⡀
  ⢿⣿⣿⣿⡿
   ⠈⠙⠋⠁ `,
      // Frame 1 - tentacles up
      `   ⣤⣤⣤
  ⢿⣿⣿⣿⡿
   ⠈⠙⠋⠁ `,
      // Frame 2 - tentacles out
      `  ⢀⣀⣀⡀
 ⢸⣿⣿⣿⣿⡇
  ⠈⠙⠋⠁  `,
      // Frame 3 - bounce
      `  ⢀⣀⣀⡀
  ⢿⣿⣿⣿⡿
   ⠘⠛⠃  `
    ];

    // Alternate ASCII Cthulhu frames
    const altFrames = [
      `     /\\___/\\
    ( o   o )
    (  =^=  )
    (        )
    (         )
   (          ))))))`,
      `     /\\___/\\
    ( O   O )
    (  =*=  )
    (        )
    (         )
   (          ))))))`,
      `     /\\___/\\
    ( -   - )
    (  =^=  )
    (        )
    (         )
   (          )))))) `
    ];

    // Simple Cthulhu frames that work well in terminal
    const simpleFrames = [
      `  {green-fg}🐙  R'lyeh{/green-fg}`,
      `  {green-fg}🦑  R'lyeh{/green-fg}`,
      `  {green-fg}🐙  R'lyeh{/green-fg}`,
      `  {green-fg}🦑  R'lyeh{/green-fg}`
    ];

    this.cthulhuInterval = setInterval(() => {
      this.cthulhuBox.setContent(simpleFrames[this.cthulhuFrame]);
      this.cthulhuFrame = (this.cthulhuFrame + 1) % simpleFrames.length;
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
    if (this.cthulhuInterval) {
      clearInterval(this.cthulhuInterval);
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
