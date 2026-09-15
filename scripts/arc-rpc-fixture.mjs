import { readFileSync } from "node:fs";
import { createServer } from "node:https";

const keyPath = process.env.OPENARC_FIXTURE_TLS_KEY;
const certPath = process.env.OPENARC_FIXTURE_TLS_CERT;
if (!keyPath || !certPath) throw new Error("Fixture TLS paths are required");

const address = "0x1111111111111111111111111111111111111111";
const to = "0x2222222222222222222222222222222222222222";
const transactionHash = `0x${"b".repeat(64)}`;
const blockHash = `0x${"a".repeat(64)}`;
const usdc = "0x3600000000000000000000000000000000000000";
const identityRegistry = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const reputationRegistry = "0x8004b663056a597dffe9eccc1965a193b7388713";
const validationRegistry = "0x8004cb1bf31daf7788923b405b754f57aceb4272";
const jobContract = "0x0747eef0706327138c69792bf28cd525089e4583";
const jobImplementation = "0xa316fd02827242d537f84730f8a37d0ba5fd351a";
const implementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const registryOwner = "0x1111111111111111111111111111111111111111";
// Reviewed ERC-8004 proxy pins (PORT-06 D7/D13). The fixture reports no drift.
const registryProxyOwner = "0x547289319c3e6aedb179c0b8e8af0b5acd062603";
const registryImplementations = new Map([
  [identityRegistry, "0x7274e874ca62410a93bd8bf61c69d8045e399c02"],
  [reputationRegistry, "0x16e0fa7f7c56b9a767e34b192b51f921be31da34"],
  [validationRegistry, "0xdb31f5d9167f8ebc8b30fbbf814c4d297c2d7f99"],
]);
const agentWallet = "0x2222222222222222222222222222222222222222";
const feedbackObserver = "0x3333333333333333333333333333333333333333";
const validationObserver = "0x4444444444444444444444444444444444444444";
const validationRequestHash = `0x${"a".repeat(64)}`;
const validationResponseHash = `0x${"b".repeat(64)}`;
const systemEmitter = "0xfffffffffffffffffffffffffffffffffffffffe";
const transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const word = (value) => `0x${value.toString(16).padStart(64, "0")}`;
const abiWord = (value) => value.toString(16).padStart(64, "0");
const abiAddress = (value) => value.slice(2).padStart(64, "0");
const abiString = (value) => {
  const encoded = Buffer.from(value, "utf8").toString("hex");
  return `${abiWord(BigInt(encoded.length / 2))}${encoded.padEnd(Math.ceil(encoded.length / 64) * 64, "0")}`;
};
const singleAddress = (value) => `0x${abiAddress(value)}`;
const singleString = (value) => `0x${abiWord(32n)}${abiString(value)}`;
const feedbackResult = () => {
  const first = abiString("delivery");
  const second = abiString("testnet");
  const headBytes = 5n * 32n;
  const secondOffset = headBytes + BigInt(first.length / 2);
  return `0x${abiWord(875n)}${abiWord(1n)}${abiWord(headBytes)}${abiWord(secondOffset)}${abiWord(0n)}${first}${second}`;
};
const validationResult = () => {
  const headBytes = 6n * 32n;
  return `0x${abiAddress(validationObserver)}${abiWord(1n)}${abiWord(91n)}${validationResponseHash.slice(2)}${abiWord(headBytes)}${abiWord(123n)}${abiString("benchmark")}`;
};
const topic = (value) => `0x${value.slice(2).padStart(64, "0")}`;
const block = { number: "0x64", hash: blockHash, timestamp: `0x${1_788_523_200n.toString(16)}` };
const transaction = { hash: transactionHash, blockHash, blockNumber: "0x64", transactionIndex: "0x2",
  from: address, to, value: "0x0" };
const log = (emitter, index, value) => ({ address: emitter,
  topics: [transferTopic, topic(address), topic(to)], data: word(value), transactionHash, blockHash,
  blockNumber: "0x64", transactionIndex: "0x2", logIndex: index, removed: false });
const receipt = { transactionHash, blockHash, blockNumber: "0x64", transactionIndex: "0x2",
  from: address, to, status: "0x1", gasUsed: "0x5208", effectiveGasPrice: "0x4a817c800",
  logs: [log(systemEmitter, "0x0", 1_000_000_000_000_000_000n), log(usdc, "0x1", 1_000_000n)] };

function result(method, params) {
  if (method === "eth_getStorageAt" && params.length === 3 && params[0] === jobContract &&
    params[1] === implementationSlot && params[2] === "0x64") return singleAddress(jobImplementation);
  if (method === "eth_getStorageAt" && params.length === 3 && registryImplementations.has(params[0]) &&
    params[1] === implementationSlot && params[2] === "0x64") return singleAddress(registryImplementations.get(params[0]));
  if (method === "eth_chainId" && params.length === 0) return "0x4cef52";
  if (method === "eth_getBlockByNumber" && params.length === 2 && params[1] === false &&
    (params[0] === "latest" || params[0] === "0x64")) return block;
  if (method === "eth_getBlockByHash" && params.length === 2 && params[0] === blockHash && params[1] === false) return block;
  if (method === "eth_getBalance" && params[0] === address && params[1] === "0x64") {
    return `0x${1_000_000_100_000_000_000n.toString(16)}`;
  }
  if (method === "eth_call" && params.length === 2 && params[1] === "0x64" &&
    params[0]?.to === usdc && params[0]?.data === `0x70a08231${address.slice(2).padStart(64, "0")}`) {
    return word(1_000_000n);
  }
  if (method === "eth_call" && params.length === 2 && params[1] === "0x64") {
    const target = params[0]?.to;
    const data = params[0]?.data;
    if (target === jobContract && data === "0x3013ce29") return singleAddress(usdc);
    if (target === jobContract && data === `0xfabc3329${abiWord(1n)}`) return word(1n);
    if (target === jobContract && data === `0xbf22c457${abiWord(1n)}`) {
      return `0x${abiWord(32n)}${abiWord(1n)}${abiAddress(registryOwner)}${abiAddress(agentWallet)}${abiAddress(feedbackObserver)}${abiWord(9n * 32n)}${abiWord(1234567890123456789012345n)}${abiWord(1788523200n)}${abiWord(2n)}${abiWord(0n)}${abiString("<script>PUBLIC_UNTRUSTED_JOB_DESCRIPTION</script>")}`;
    }
    if (target === identityRegistry && data === `0x6352211e${abiWord(1n)}`) return singleAddress(registryOwner);
    if (target === identityRegistry && data === `0xc87b56dd${abiWord(1n)}`) return singleString("https://example.test/agent.json");
    if (target === identityRegistry && data === `0x00339509${abiWord(1n)}`) return singleAddress(agentWallet);
    if ((target === reputationRegistry || target === validationRegistry) && data === "0xbc4d861b") {
      return singleAddress(identityRegistry);
    }
    if (target === reputationRegistry && data === `0x232b0810${abiWord(1n)}${abiAddress(feedbackObserver)}${abiWord(0n)}`) {
      return feedbackResult();
    }
    if (target === validationRegistry && data === `0xff2febfc${validationRequestHash.slice(2)}`) return validationResult();
    if (registryImplementations.has(target) && data === "0x8da5cb5b") return singleAddress(registryProxyOwner);
  }
  if (method === "eth_getTransactionByHash" && params[0] === transactionHash) return transaction;
  if (method === "eth_getTransactionReceipt" && params[0] === transactionHash) return receipt;
  return null;
}

const server = createServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, (request, response) => {
  if (request.method !== "POST" || request.url !== "/") {
    response.writeHead(404, { "Content-Type": "application/json" }).end("{}");
    return;
  }
  const chunks = [];
  let bytes = 0;
  request.on("data", (chunk) => {
    bytes += chunk.length;
    if (bytes > 16_384) request.destroy();
    else chunks.push(chunk);
  });
  request.on("end", () => {
    try {
      const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (!input || input.jsonrpc !== "2.0" || typeof input.id !== "string" ||
        typeof input.method !== "string" || !Array.isArray(input.params)) throw new Error("invalid fixture request");
      const body = JSON.stringify({ jsonrpc: "2.0", id: input.id, result: result(input.method, input.params) });
      response.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body),
        "Cache-Control": "no-store" }).end(body);
    } catch {
      response.writeHead(400, { "Content-Type": "application/json" }).end("{}");
    }
  });
});

server.listen(443, "0.0.0.0", () => process.stdout.write("fixture_ready\n"));
const shutdown = () => server.close(() => process.exit(0));
process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
