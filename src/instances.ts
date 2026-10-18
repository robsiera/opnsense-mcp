import type { Config } from "./config.js";
import { resolveTarget } from "./config.js";
import { OPNsenseClient } from "./client.js";
import { Diagnostics } from "./diagnostics.js";
import type { OpnsenseTarget } from "./types.js";

export type ResolvedInstance = {
  name: string;
  target: OpnsenseTarget;
  client: OPNsenseClient;
  diagnostics: Diagnostics;
};

export class InstanceRegistry {
  readonly #config: Config;
  readonly #clients = new Map<string, OPNsenseClient>();
  readonly #diagnostics = new Map<string, Diagnostics>();

  constructor(config: Config) {
    this.#config = config;
    for (const target of config.instances) {
      const client = new OPNsenseClient(target);
      this.#clients.set(target.name, client);
      this.#diagnostics.set(target.name, new Diagnostics(client));
    }
  }

  get defaultInstance(): string {
    return this.#config.defaultInstance;
  }

  list(): Array<{ name: string; target: string; writeMode: OpnsenseTarget["writeMode"]; isDefault: boolean }> {
    return this.#config.instances.map((target) => ({
      name: target.name,
      target: target.baseUrl.origin,
      writeMode: target.writeMode,
      isDefault: target.name === this.#config.defaultInstance,
    }));
  }

  resolve(instance?: string | undefined): ResolvedInstance {
    const target = resolveTarget(this.#config, instance);
    const client = this.#clients.get(target.name);
    const diagnostics = this.#diagnostics.get(target.name);
    if (!client || !diagnostics) {
      throw new Error(`Internal error: instance "${target.name}" is not registered`);
    }
    return { name: target.name, target, client, diagnostics };
  }

  async close(): Promise<void> {
    await Promise.all([...this.#clients.values()].map((client) => client.close()));
  }
}
