import fs from 'node:fs';
import { bookingPayload, prepareMarketTransaction } from '../compute/market.mjs';
import { readMarketOffers, readMarketBookings } from '../compute/market_reader.mjs';

const [command, contextFile, inputFile] = process.argv.slice(2);
try {
  if (!['booking-payload', 'prepare', 'offers', 'bookings'].includes(command) || !contextFile || !inputFile || process.argv.length !== 5)
    throw Error('Usage: node scripts/compute-market.mjs booking-payload|prepare|offers|bookings context.json input.json');
  const read = file => {
    const bytes = fs.readFileSync(file);
    if (bytes.length > 1024 * 1024) throw Error('Input exceeds 1 MiB');
    return JSON.parse(bytes.toString('utf8'));
  };
  const context = read(contextFile), input = read(inputFile);
  const result = command === 'booking-payload' ? bookingPayload(context, input) : command === 'prepare' ? prepareMarketTransaction(context, input) :
    command === 'offers' ? await readMarketOffers(context, input) : await readMarketBookings(context, input);
  console.log(JSON.stringify(result,
    (_, value) => typeof value === 'bigint' ? value.toString() : value, 2));
} catch (error) { console.error(error.message); process.exitCode = 1; }
