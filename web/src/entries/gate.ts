// Gate page entry: drives the PassKey registration (first visit) and
// authentication ceremonies against /__passgate/api/*.
import { startAuthentication, startRegistration } from '@simplewebauthn/browser'

const body = document.body
const registered = body.dataset.registered === 'true'
const next = body.dataset.next || '/'

const button = document.querySelector<HTMLButtonElement>('#gate-action')
const status = document.querySelector<HTMLElement>('#gate-status')
const setupKeyInput = document.querySelector<HTMLInputElement>('#setup-key')

const setupKeyHeader = 'X-Passgate-Setup-Key'

function showError(message: string) {
  if (status) {
    status.textContent = message
    status.classList.remove('hidden')
  }
}

async function post(url: string, payload?: unknown, extraHeaders?: Record<string, string>): Promise<Response> {
  const headers: Record<string, string> = { ...extraHeaders }
  if (payload !== undefined) headers['Content-Type'] = 'application/json'
  const resp = await fetch(url, {
    method: 'POST',
    headers: Object.keys(headers).length ? headers : undefined,
    body: payload === undefined ? undefined : JSON.stringify(payload),
  })
  if (!resp.ok) {
    let message = `request failed (${resp.status})`
    try {
      const data = await resp.json()
      if (data?.error) message = data.error
    } catch {
      // not a JSON error body
    }
    throw new Error(message)
  }
  return resp
}

async function run() {
  if (registered) {
    const begin = await (await post('/__passgate/api/login/begin')).json()
    const assertion = await startAuthentication({ optionsJSON: begin.publicKey })
    await post('/__passgate/api/login/finish', assertion)
  } else {
    const key = setupKeyInput?.value.trim() ?? ''
    if (!key) {
      throw new Error('Enter the setup key printed in the server terminal')
    }
    const headers = { [setupKeyHeader]: key }
    const begin = await (await post('/__passgate/api/register/begin', undefined, headers)).json()
    const attestation = await startRegistration({ optionsJSON: begin.publicKey })
    await post('/__passgate/api/register/finish', attestation, headers)
  }
  window.location.href = next
}

setupKeyInput?.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    event.preventDefault()
    button?.click()
  }
})

button?.addEventListener('click', async () => {
  button.disabled = true
  try {
    await run()
  } catch (err) {
    showError(err instanceof Error ? err.message : String(err))
    button.disabled = false
  }
})

export {}
