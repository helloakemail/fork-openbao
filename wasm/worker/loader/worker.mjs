// Cloudflare loader for the OpenBao core compiled to Go js/wasm.
//
// The core runs inside ONE Durable Object instance ("singleton"). A plain
// Worker cannot host it: every socket and timer belongs to the request that
// created it, so OpenBao's background goroutines (lease expiry, rollback, kv
// upgrades) stall as soon as their request returns. A Durable Object keeps a
// single long-lived context, stays alive while outbound sockets are open, and
// serialises access, which also removes the "every isolate is the active
// node" problem.
//
// The stateless Worker in front forwards every request to that object.

import { DurableObject } from "cloudflare:workers";
import "./wasm_exec.js";
import { createRuntimeContext, loadModule } from "./runtime.mjs";

globalThis.tryCatch = (fn) => {
  try {
    return { result: fn() };
  } catch (e) {
    return { error: e };
  }
};

// Route Go's stdout/stderr straight to the console, unbuffered, so panics and
// runtime fatals are visible in the logs even when the program exits.
{
  const dec = new TextDecoder();
  let pending = "";
  globalThis.fs.writeSync = (fd, buf) => {
    pending += dec.decode(buf);
    const nl = pending.lastIndexOf("\n");
    if (nl !== -1) {
      const line = pending.substring(0, nl);
      pending = pending.substring(nl + 1);
      (fd === 2 ? console.error : console.log)("[go] " + line);
    }
    return buf.length;
  };
}

let mod;

async function startGo(env, ctx) {
  if (mod === undefined) {
    mod = await loadModule();
  }
  const binding = {};
  const go = new Go();
  let ready;
  const readyPromise = new Promise((resolve) => {
    ready = resolve;
  });
  const instance = new WebAssembly.Instance(mod, {
    ...go.importObject,
    workers: { ready: () => ready() },
  });
  // Expose the linear memory so the Go side can report its true size (Go's
  // MemStats.Sys excludes the data segment).
  globalThis.__wasmMemory = instance.exports.mem;
  go.run(instance, createRuntimeContext({ env, ctx, binding }));
  await readyPromise;
  return { go, binding };
}

export class OpenBaoCore extends DurableObject {
  constructor(state, env) {
    super(state, env);
    this.state = state;
    this.env = env;
    this.starting = undefined;
  }

  ensureStarted() {
    if (!this.starting) {
      this.starting = startGo(this.env, this.state).catch((err) => {
        this.starting = undefined;
        throw err;
      });
    }
    return this.starting;
  }

  async fetch(req) {
    const { binding } = await this.ensureStarted();
    return binding.handleRequest(req);
  }
}

export default {
  async fetch(req, env) {
    const id = env.OPENBAO.idFromName("singleton");
    return env.OPENBAO.get(id).fetch(req);
  },
};
