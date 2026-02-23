#!/usr/bin/env node

/**
 * Test script for modern terminal UI
 * Demonstrates the new ora + boxen + cli-table3 approach
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
  gui.section('Initializing Okta Security Health Check');
  await sleep(300);

  gui.success('Configuration loaded');
  await sleep(300);

  gui.success('Okta API connection verified');
  await sleep(300);

  // Test loading with spinner
  gui.progress('Fetching latest detection rules from GitHub');
  await sleep(2000);
  gui.success('Loaded 35 detection rules and hunts');
  await sleep(500);

  // Test detection section
  gui.section('Running Security Checks');
  await sleep(300);

  // Simulate running detections
  for (let i = 1; i <= 5; i++) {
    const detections = [
      { title: 'Admin Console Access Denied', type: 'detection', findings: 3 },
      { title: 'MFA Abandonment Detection', type: 'detection', findings: 0 },
      { title: 'Password Spray Attack', type: 'detection', findings: 5 },
      { title: 'Suspicious AD User Imports', type: 'hunt', findings: 2 },
      { title: 'API Token Creation', type: 'detection', findings: 1 }
    ];

    const det = detections[i - 1];
    gui.detection(i, 35, det.title, det.type);
    await sleep(1500);
    gui.finding(det.findings);
    await sleep(300);

    // Show sample events for detections with findings
    if (det.findings > 0 && i <= 2) {
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
          result: 'FAILURE',
          reason: 'Invalid credentials'
        }
      });
      await sleep(300);
    }
  }

  console.log(chalk.gray('\n... (30 more checks completed) ...\n'));
  await sleep(500);

  // Test correlation analysis
  gui.section('Performing Correlation Analysis');
  await sleep(300);

  gui.info('Analyzing events to identify patterns and risk indicators');
  await sleep(1000);

  console.log('\n' + chalk.bold('🔍 Entities Found in Multiple Detections:\n'));

  gui.riskUser(1, 'compromised.user@example.com', 'CRITICAL', 180);
  await sleep(200);

  gui.riskUser(2, 'admin@example.com', 'HIGH', 120);
  await sleep(200);

  gui.riskUser(3, 'developer@example.com', 'MODERATE', 75);
  await sleep(200);

  console.log('\n' + chalk.bold('🌐 High-Risk IP Addresses:\n'));

  gui.riskIP(1, '192.168.1.100', 'CRITICAL', 150);
  await sleep(200);

  gui.riskIP(2, '10.0.0.45', 'HIGH', 110);
  await sleep(200);

  // Test summary table
  gui.section('Scan Summary');

  gui.summaryTable({
    'Total Checks': '35/35 completed',
    'With Findings': '8 detections/hunts',
    'Total Events': '247 events found',
    'Execution Time': '2m 15s'
  });

  // Risk summary
  console.log('\n' + chalk.bold.cyan('Risk Analysis:'));
  gui.riskSummaryTable({
    'CRITICAL': { count: 2, users: ['compromised.user@example.com', 'attacker@example.com'] },
    'HIGH': { count: 5, users: ['admin@example.com', 'admin2@example.com', 'admin3@example.com'] },
    'MODERATE': { count: 12, users: ['developer@example.com', 'user1@example.com', 'user2@example.com'] },
    'LOW': { count: 18, users: ['user3@example.com', 'user4@example.com', 'user5@example.com'] }
  });

  // Generate PDF
  await sleep(500);
  gui.section('Generating PDF Report');
  gui.progress('Creating PDF document');
  await sleep(2000);
  gui.success('PDF report saved: ./reports/healthcheck-2024-02-23.pdf');

  // Show elapsed time
  gui.showElapsedTime();

  console.log('\n' + chalk.bold.green('✓ Scan complete!') + chalk.gray(' All security checks finished.\n'));
}

// Add chalk for the demo
const chalk = require('chalk');

// Run demo
demo().catch(console.error);
