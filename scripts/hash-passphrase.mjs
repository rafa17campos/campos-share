#!/usr/bin/env node
/**
 * Prints the scrypt hash of a passphrase, to be stored in MCP_LOGIN_PASSPHRASE_HASH.
 *
 *   npm run passphrase:hash            # prompts without echo
 *   npm run passphrase:hash -- 'text'  # hashes the argument (visible in shell history)
 */

import readline from 'node:readline';
import { hashPassword } from '../lib/auth.ts';

const MIN_LENGTH = 12;

function promptHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    let muted = false;
    const write = rl._writeToOutput.bind(rl);
    rl._writeToOutput = (text) => {
      if (!muted) write(text);
    };
    rl.question(question, (answer) => {
      muted = false;
      process.stdout.write('\n');
      rl.close();
      resolve(answer);
    });
    muted = true;
  });
}

const fromArg = process.argv[2];
const passphrase = fromArg ?? (process.stdin.isTTY ? await promptHidden('Passphrase: ') : (await new Response(process.stdin).text()).replace(/\r?\n$/, ''));

if (!passphrase || passphrase.length < MIN_LENGTH) {
  console.error(`Use a passphrase of at least ${MIN_LENGTH} characters.`);
  process.exit(1);
}

console.log(await hashPassword(passphrase));
