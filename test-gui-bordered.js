#!/usr/bin/env node

/**
 * Test script for bordered terminal GUI
 * Tests the layout with header and log borders
 */

const gui = require('./src/terminalGui');

// Initialize GUI with mock config
gui.initialize({
  okta: {
    domain: 'example.okta.com'
  }
});

// Test logging
setTimeout(() => {
  gui.section('Testing Bordered Layout');
  gui.success('Header has border and fixed position');
  gui.info('Log area has border below header');
  gui.warning('Owl mascot is positioned inside header');

  gui.log('\n');
  gui.detection(1, 5, 'Test Detection', 'detection');
  gui.log('This is a test detection description');
  gui.finding(0);

  gui.log('\n');
  gui.detection(2, 5, 'Test Hunt', 'hunt');
  gui.log('This is a test hunt description');
  gui.finding(3);

  // Add some sample events
  gui.log('\n');
  gui.event(1, {
    published: '2024-02-23T10:30:00Z',
    eventType: 'user.authentication.auth_via_mfa',
    actor: { alternateId: 'john.doe@example.com' },
    client: {
      ipAddress: '192.168.1.100',
      geographicalContext: {
        city: 'San Francisco',
        state: 'California',
        country: 'United States'
      }
    },
    outcome: {
      result: 'SUCCESS'
    }
  });

  // Test scrolling with many lines
  gui.log('\n');
  gui.section('Scrolling Test');
  for (let i = 1; i <= 50; i++) {
    gui.log(`{gray-fg}Line ${i} - Testing scrolling behavior...{/gray-fg}`);
  }

  gui.log('\n');
  gui.section('Risk Analysis');
  gui.riskUser(1, 'user@example.com', 'CRITICAL', 180);
  gui.riskIP(1, '192.168.1.100', 'HIGH', 120);

  gui.log('\n{bold}{green-fg}✓ Test complete! Header should stay visible. Press ESC or Q to exit.{/green-fg}{/bold}');

}, 1000);
