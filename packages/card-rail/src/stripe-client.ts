/**
 * Minimal Stripe Issuing REST client — only the four calls the card door
 * needs, fetch-based, form-encoded, zero dependencies. The base URL is
 * injectable so CI runs against a local mock and the live smoke against
 * real test mode; the secret key is injected by the door and never logged
 * (R2). Webhook handling does NOT go through this client — decisions are
 * pushed to us, not pulled.
 */

const STRIPE_API_BASE = 'https://api.stripe.com';
const REQUEST_TIMEOUT_MS = 20_000;

export class StripeApiError extends Error {
  readonly status: number;
  readonly stripeType: string | null;
  readonly stripeCode: string | null;

  constructor(status: number, stripeType: string | null, stripeCode: string | null, message: string) {
    super(message);
    this.name = 'StripeApiError';
    this.status = status;
    this.stripeType = stripeType;
    this.stripeCode = stripeCode;
  }
}

export interface StripeCardholder {
  id: string;
  object: string;
  name: string;
  status: string;
}

export interface StripeCard {
  id: string;
  object: string;
  last4: string;
  status: string;
  currency: string;
  cardholder?: { id: string } | string;
}

type FormValue = string | number | boolean | FormParams | FormValue[];
interface FormParams {
  [key: string]: FormValue;
}

/** Stripe's nested bracket form encoding: {a:{b:1}, c:[x]} → a[b]=1&c[0]=x. */
export function encodeForm(params: FormParams, prefix = ''): string[] {
  const pairs: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    const name = prefix === '' ? key : `${prefix}[${key}]`;
    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (typeof item === 'object' && item !== null && !Array.isArray(item)) {
          pairs.push(...encodeForm(item, `${name}[${index}]`));
        } else {
          pairs.push(`${encodeURIComponent(`${name}[${index}]`)}=${encodeURIComponent(String(item))}`);
        }
      });
    } else if (typeof value === 'object' && value !== null) {
      pairs.push(...encodeForm(value, name));
    } else {
      pairs.push(`${encodeURIComponent(name)}=${encodeURIComponent(String(value))}`);
    }
  }
  return pairs;
}

export class StripeClient {
  private readonly baseUrl: string;
  private readonly secretKey: string;
  private readonly apiVersion: string | null;
  private readonly fetchImpl: typeof fetch;

  constructor(args: {
    secretKey: string;
    baseUrl?: string;
    /**
     * Optional pinned Stripe-Version for outbound calls. Absent = the
     * account's default version (an operator choice, never invented here).
     */
    apiVersion?: string;
    fetchImpl?: typeof fetch;
  }) {
    this.secretKey = args.secretKey;
    this.baseUrl = (args.baseUrl ?? STRIPE_API_BASE).replace(/\/+$/, '');
    this.apiVersion = args.apiVersion ?? null;
    this.fetchImpl = args.fetchImpl ?? fetch;
  }

  async createCardholder(args: {
    name: string;
    email?: string;
    line1: string;
    city: string;
    postalCode: string;
    country: string;
  }): Promise<StripeCardholder> {
    return (await this.request('POST', '/v1/issuing/cardholders', {
      name: args.name,
      type: 'individual',
      ...(args.email === undefined ? {} : { email: args.email }),
      billing: {
        address: {
          line1: args.line1,
          city: args.city,
          postal_code: args.postalCode,
          country: args.country,
        },
      },
    })) as StripeCardholder;
  }

  /**
   * Create a single-use virtual card. The Stripe-side per-authorization
   * spending limit mirrors the mandate's per-tx cap — belt-and-suspenders
   * only; the AUTHORITATIVE decision is our authorization webhook.
   */
  async createCard(args: {
    cardholderId: string;
    currency: string;
    perAuthorizationLimitMinorUnits: number;
    metadata: Record<string, string>;
  }): Promise<StripeCard> {
    return (await this.request('POST', '/v1/issuing/cards', {
      cardholder: args.cardholderId,
      currency: args.currency.toLowerCase(),
      type: 'virtual',
      status: 'active',
      spending_controls: {
        spending_limits: [
          { amount: args.perAuthorizationLimitMinorUnits, interval: 'per_authorization' },
        ],
      },
      metadata: args.metadata,
    })) as StripeCard;
  }

  async cancelCard(cardId: string): Promise<StripeCard> {
    return (await this.request('POST', `/v1/issuing/cards/${encodeURIComponent(cardId)}`, {
      status: 'canceled',
    })) as StripeCard;
  }

  async getCard(cardId: string): Promise<StripeCard> {
    return (await this.request('GET', `/v1/issuing/cards/${encodeURIComponent(cardId)}`)) as StripeCard;
  }

  private async request(method: 'GET' | 'POST', path: string, params?: FormParams): Promise<unknown> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${this.secretKey}`,
      ...(this.apiVersion === null ? {} : { 'stripe-version': this.apiVersion }),
    };
    let body: string | undefined;
    if (method === 'POST') {
      headers['content-type'] = 'application/x-www-form-urlencoded';
      body = encodeForm(params ?? {}).join('&');
    }
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new StripeApiError(response.status, null, null, `Stripe returned non-JSON (HTTP ${response.status})`);
    }
    if (!response.ok) {
      const error = (parsed as { error?: { type?: string; code?: string; message?: string } }).error;
      // Stripe error messages are safe to surface (they never echo the key),
      // but keep them short and typed.
      throw new StripeApiError(
        response.status,
        error?.type ?? null,
        error?.code ?? null,
        `Stripe ${method} ${path} failed (HTTP ${response.status}): ${error?.message ?? 'unknown error'}`
      );
    }
    return parsed;
  }
}
