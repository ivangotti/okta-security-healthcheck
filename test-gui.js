#!/usr/bin/env node

// Test script to verify terminal GUI
const gui = require('./src/terminalGui');

async function testGui() {
  // Initialize GUI with mock config
  const mockConfig = {
    okta: {
      domain: 'test-company.okta.com'
    }
  };
  gui.initialize(mockConfig);

  // Test different logging methods
  gui.section('Testing Terminal GUI');

  await sleep(500);
  gui.success('This is a success message');

  await sleep(500);
  gui.error('This is an error message');

  await sleep(500);
  gui.warning('This is a warning message');

  await sleep(500);
  gui.info('This is an info message');

  await sleep(500);
  gui.section('Testing Detection Display');

  await sleep(500);
  gui.detection(1, 10, 'Test Detection Name', 'detection');

  await sleep(500);
  gui.log('{gray-fg}This is a test description of the detection{/gray-fg}');

  await sleep(500);
  gui.finding(3);

  await sleep(500);
  gui.event(1, {
    published: '2026-02-23T14:00:00.000Z',
    eventType: 'user.authentication.auth_via_mfa',
    actor: { alternateId: 'test.user@company.com' },
    client: {
      ipAddress: '192.168.1.100',
      geographicalContext: {
        city: 'San Francisco',
        state: 'California',
        country: 'United States'
      }
    },
    outcome: { result: 'SUCCESS' }
  });

  await sleep(500);
  gui.section('Testing Risk Display');

  await sleep(500);
  gui.riskUser(1, 'suspicious.user@company.com', 'CRITICAL', 187);

  await sleep(500);
  gui.riskIP(1, '203.0.113.50', 'HIGH', 142);

  await sleep(1000);
  gui.log('\n{green-fg}{bold}✅ GUI Test Complete! Watch the owl mascot with different expressions!{/bold}{/green-fg}');
  gui.log('{cyan-fg}Notice the black background and Okta org URL in the header!{/cyan-fg}');
  gui.log('{cyan-fg}The owl shows 8 different expressions as it animates!{/cyan-fg}');
  gui.log('{cyan-fg}Exiting in 5 seconds...{/cyan-fg}');

  // Increase timeout to see more animation frames
  setTimeout(() => {
    gui.cleanup();
    process.exit(0);
  }, 5000);

}


function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

testGui();
