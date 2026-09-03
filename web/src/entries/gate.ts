// Gate page entry: drives the PassKey registration (first visit) and
// authentication ceremonies against /__passgate/api/*.
import { startAuthentication, startRegistration } from '@simplewebauthn/browser'

const body = document.body
const registered = body.dataset.registered === 'true'
const next = body.dataset.next || '/'

const button = document.querySelector<HTMLButtonElement>('#gate-action')
const status = document.querySelector<HTMLElement>('#gate-status')

function showError(message: string) {
  if (status) {
    status.textContent = message
    status.classList.remove('hidden')
  }
}

async function post(url: string, payload?: unknown): Promise<Response> {
  const resp = await fetch(url, {
    method: 'POST',
    headers: payload === undefined ? undefined : { 'Content-Type': 'application/json' },
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
    const begin = await (await post('/__passgate/api/register/begin')).json()
    const attestation = await startRegistration({ optionsJSON: begin.publicKey })
    await post('/__passgate/api/register/finish', attestation)
  }
  window.location.href = next
}

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
