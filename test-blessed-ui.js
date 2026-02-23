#!/usr/bin/env node

/**
 * Test script for blessed terminal UI with enhanced event formatting
 */

const gui = require('./src/terminalGui');

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function demo() {
  // Initialize GUI with mock config
  gui.initialize({
    okta: {
      domain: 'example.okta.com'
    }
  });

  await sleep(500);

  // Test section
  gui.section('Testing Blessed UI with Enhanced Event Formatting');
  await sleep(500);

  gui.success('Configuration loaded');
  await sleep(300);

  gui.success('Okta API connection verified');
  await sleep(300);

  gui.info('Loaded 35 detection rules and hunts');
  await sleep(500);

  // Test detection
  gui.section('Running Security Checks');
  await sleep(300);

  gui.detection(1, 35, 'Admin Console Access Denied', 'detection');
  gui.log('Checking for unauthorized admin console access attempts...');
  await sleep(800);

  gui.finding(3);
  await sleep(300);

  // Sample event 1 - FAILURE with detailed context
  gui.event(1, {
    published: '2024-02-23T14:30:45.000Z',
    eventType: 'user.session.access_admin_app',
    actor: {
      alternateId: 'compromised.user@example.com',
      displayName: 'John Doe'
    },
    client: {
      ipAddress: '203.0.113.42',
      userAgent: {
        rawUserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
      },
      geographicalContext: {
        city: 'Moscow',
        state: 'Moscow',
        country: 'Russia'
      },
      device: 'Computer'
    },
    outcome: {
      result: 'FAILURE',
      reason: 'VERIFICATION_ERROR'
    },
    target: [{
      displayName: 'Okta Admin Console',
      type: 'AppInstance'
    }],
    debugContext: {
      debugData: {
        requestUri: '/admin/dashboard'
      }
    }
  });
  await sleep(500);

  // Sample event 2 - DENY
  gui.event(2, {
    published: '2024-02-23T14:32:18.000Z',
    eventType: 'user.authentication.auth_via_mfa',
    actor: {
      alternateId: 'attacker@example.com',
      displayName: 'Unknown User'
    },
    client: {
      ipAddress: '198.51.100.73',
      geographicalContext: {
        city: 'Beijing',
        state: 'Beijing',
        country: 'China'
      }
    },
    outcome: {
      result: 'DENY',
      reason: 'User attempted to authenticate from blocked country'
    }
  });
  await sleep(500);

  // Sample event 3 - SUCCESS
  gui.event(3, {
    published: '2024-02-23T14:35:01.000Z',
    eventType: 'user.session.start',
    actor: {
      alternateId: 'admin@example.com',
      displayName: 'Admin User'
    },
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
  await sleep(500);

  // Test another detection
  gui.log('\n');
  gui.detection(2, 35, 'Password Spray Attack', 'detection');
  gui.log('Detecting password spray attacks across multiple accounts...');
  await sleep(800);

  gui.finding(5);
  await sleep(300);

  // Test hunt
  gui.log('\n');
  gui.detection(15, 35, 'Suspicious API Activity', 'hunt');
  gui.log('Hunting for unusual API token usage patterns...');
  await sleep(800);

  gui.finding(2);
  await sleep(300);

  // Test correlation
  gui.section('Performing Correlation Analysis');
  await sleep(500);

  gui.log('{gray-fg}🔬 Analyzing events to identify patterns and risk indicators...{/gray-fg}\n');
  await sleep(1000);

  gui.log('{bold}{white-fg}🔍 Entities Found in Multiple Detections:{/white-fg}{/bold}\n');

  gui.riskUser(1, 'compromised.user@example.com', 'CRITICAL', 180);
  await sleep(200);

  gui.riskUser(2, 'admin@example.com', 'HIGH', 120);
  await sleep(200);

  gui.riskUser(3, 'developer@example.com', 'MODERATE', 75);
  await sleep(200);

  gui.log('\n{bold}{white-fg}🌐 High-Risk IP Addresses:{/white-fg}{/bold}\n');

  gui.riskIP(1, '203.0.113.42', 'CRITICAL', 150);
  await sleep(200);

  gui.riskIP(2, '198.51.100.73', 'HIGH', 110);
  await sleep(200);

  // Summary
  gui.section('Scan Summary');
  await sleep(300);

  gui.success('Completed 35/35 security checks');
  gui.warning('8 detections/hunts with findings');
  gui.info('247 total events analyzed');

  gui.log('\n{green-fg}{bold}✓ Scan complete! Press ESC or Q to exit.{/bold}{/green-fg}');

  // Auto-exit after 3 seconds for demo
  await sleep(3000);
  gui.cleanup();
  process.exit(0);
}

// Run demo
demo().catch(console.error);
