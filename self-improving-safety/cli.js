#!/usr/bin/env node

/**
 * ClawGuard Self-Improving Safety CLI
 * Command-line interface for safety rule management and learning
 */

const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const chalk = require('chalk');
const SafetyModule = require('./src/safety');

const safety = new SafetyModule();

yargs(hideBin(process.argv))
  .command('monitor', 'Listen for threat alerts and learn from them', {}, (argv) => {
    console.log(chalk.blue('Starting Self-Improving Safety Monitor...'));
    console.log(chalk.gray('(Listening for JSON threat alerts on stdin...)'));
    
    process.stdin.setEncoding('utf8');
    
    let buffer = '';
    
    process.stdin.on('data', (chunk) => {
      buffer += chunk;
      const lines = buffer.split('\n');
      buffer = lines.pop(); // Keep incomplete line in buffer
      
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          // Attempt to parse line as JSON directly or check if it contains JSON
          // Ideally detect-skill output should be structured. 
          // For this demo, we assume structured JSON input or text we can parse.
          // Fallback: simple text parsing if known format
          if (line.includes('THREAT DETECTED') || line.trim().startsWith('{')) {
             // In a real integration, we'd parse the structured alert.
             // Here we simulate learning from a raw line if it looks like a threat.
             safety.processThreat({ raw: line, timestamp: new Date() });
          }
        } catch (e) {
          console.error(chalk.red('Error parsing input:'), e.message);
        }
      }
    });
    
    process.stdin.on('end', () => {
       console.log(chalk.blue('Monitor stream ended.'));
    });
  })
  .command('add-rule <type> <pattern>', 'Manually add a blocking rule', (yargs) => {
    yargs
      .positional('type', { describe: 'Rule type (command, file, network)', type: 'string' })
      .positional('pattern', { describe: 'Regex or string pattern to block', type: 'string' });
  }, (argv) => {
    safety.addRule(argv.type, argv.pattern);
    console.log(chalk.green(`Rule added: [${argv.type}] ${argv.pattern}`));
  })
  .command('check <input>', 'Check if input is blocked by current rules', (yargs) => {
    yargs.positional('input', { describe: 'Command or string to check', type: 'string' });
  }, (argv) => {
    const result = safety.checkInput(argv.input);
    if (result.blocked) {
      console.log(chalk.red('🚫 BLOCKED'));
      console.log(`   Reason: matched rule [${result.rule.type}] ${result.rule.pattern}`);
    } else {
      console.log(chalk.green('✅ ALLOWED'));
    }
  })
  .command('list', 'List active safety rules', {}, () => {
    const rules = safety.getRules();
    console.log(chalk.bold(`Active Safety Rules (${rules.length}):`));
    rules.forEach((rule, idx) => {
      console.log(`  ${idx + 1}. [${chalk.yellow(rule.type)}] ${rule.pattern} (Hits: ${rule.hits || 0})`);
    });
  })
  .command('learn', 'Learn from piped threat details (one-shot)', {}, async () => {
    // Read all from stdin then process
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const input = Buffer.concat(chunks).toString();
    
    if (input.trim()) {
       console.log(chalk.blue('Analyzing threat report...'));
       // Simple heuristic: if input contains "Action: Block" or "Severity: High", treat as threat
       if (input.includes('Severity: High') || input.includes('THREAT DETECTED')) {
         // Extract command if possible (simulated)
         const cmdMatch = input.match(/Command:\s*(.+)/i) || input.match(/Analyzing command:\s*(.+)/i);
         if (cmdMatch) {
            const cmd = cmdMatch[1].trim();
            safety.addRule('command', cmd); // In reality, we'd want to generalize this
            console.log(chalk.green(`Learned new rule for command: ${cmd}`));
         } else {
            console.log(chalk.yellow('Threat detected but could not extract specific pattern to block.'));
         }
       } else {
         console.log(chalk.gray('No actionable low-level threats found in report.'));
       }
    }
  })
  .demandCommand(1)
  .help()
  .argv;
