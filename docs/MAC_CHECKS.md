# Checks to run on a Mac

Some parts of Opfence have only been tested on Linux, because the build environment has no Mac, no signed-in agents and no phone: the macOS sandbox, the keychain, desktop dialogs, Cursor and Gemini CLI, and phone approvals through ntfy.sh. This list covers them. It takes about an hour and a half, and every step uses a **fake Railway token**, so Railway refuses every call it receives. Even if you approve a deletion, nothing in any account can change.

Write down what each step prints next to its checkbox, especially anything marked **Send back**. A failed step is useful: note it and carry on.

## 0. Set up

- [ ] **Go and Opfence.** Go 1.26.9 or newer (`brew install go`), then:

  ```sh
  go install github.com/rakeshnitb23/opfence/cmd/opfence@latest
  opfence version
  ```

  If `opfence` is not found, add Go's bin folder to your PATH: `export PATH="$HOME/go/bin:$PATH"`.

- [ ] **Claude Code 2.1.285 or newer**, signed in: `claude --version` (update with `claude update`).
- [ ] **Anthropic's sandbox runtime** (for Cursor and Gemini): `npm install -g @anthropic-ai/sandbox-runtime`, then `srt --version`.
- [ ] **A scratch folder** with the fake token and a script that sends one Railway call:

  ```sh
  mkdir -p ~/opfence-check && cd ~/opfence-check && git init -q
  printf 'RAILWAY_API_TOKEN=00000000-1111-2222-3333-444444444444\n' > .env
  cat > railway.sh <<'EOF'
  #!/bin/sh
  # Sends one Railway API call. The token is fake, so Railway refuses every
  # call it receives: nothing in any account can change.
  # Usage: sh railway.sh read | rename | delete
  [ -f .env ] && . ./.env
  case "$1" in
    read)   q='query { me { id } }' ;;
    rename) q='mutation { volumeUpdate(volumeId: \"vol-test\", input: {name: \"renamed\"}) }' ;;
    delete) q='mutation { volumeDelete(volumeId: \"vol-test\") }' ;;
    *) echo "usage: sh railway.sh read | rename | delete"; exit 2 ;;
  esac
  curl -sS -X POST https://backboard.railway.com/graphql/v2 \
    -H "Authorization: Bearer $RAILWAY_API_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"$q\"}"
  echo
  EOF
  ```

  The three calls, as Opfence decides them in production (every id counts as production until you map it):

  | Command | What it asks Railway | Class | Decision |
  | --- | --- | --- | --- |
  | `sh railway.sh read` | who am I | read | allow: runs, Railway answers "Not Authorized" |
  | `sh railway.sh rename` | rename volume vol-test | write | ask: held until you approve |
  | `sh railway.sh delete` | delete volume vol-test | irreversible | confirm: held until you type `vol-test` |

## 1. Doctor, keychain and init (outside any agent)

- [ ] `opfence doctor`. **Send back** the whole output. Before step 2 the CA is expected to show as not trusted; anything else that fails is worth knowing. If srt is installed, doctor also runs the sandbox checks through it.
- [ ] `opfence init` in `~/opfence-check`, and answer yes. It should find the Railway key in `.env` and store it in your login keychain. If macOS asks whether `security` may use the keychain, note it (**send back** the exact wording) and allow it.
- [ ] `cat .env`: the value is now a different UUID, a placeholder of the same shape. `opfence secrets list` lists the Railway key without its value.
- [ ] Open **Keychain Access** and search for `opfence`: there is an entry whose service is `opfence`.

## 2. Trust the CA

- [ ] `opfence trust`. macOS asks for your password to add Opfence's CA to your login keychain. Then `opfence doctor` shows the CA as trusted.
- [ ] Note: the CA can only issue certificates for API domains in the catalog (X.509 name constraints). `opfence trust --uninstall` removes it again at the end, if you want.

## 3. Claude Code under `opfence run`

Start it from the scratch folder:

```sh
cd ~/opfence-check && opfence run -- claude
```

- [ ] It starts and prints an Opfence session line (strict mode, sandbox on). **Send back** that banner and any warnings.
- [ ] Ask Claude: *"Run `echo $RAILWAY_API_TOKEN` and `cat .env`."* Both show the placeholder, never `00000000-1111-…`.
- [ ] Ask Claude: *"Run `sh railway.sh read`."* It prints Railway's `Not Authorized` error. That means the call went through Opfence to Railway.
- [ ] Ask Claude: *"Run `sh railway.sh delete`."* A **macOS dialog** appears with the card "Delete Railway volume vol-test and all data on it", irreversible, production. Click **Deny**. Claude gets a JSON error that says a human denied it.
- [ ] Run the delete again and this time type `vol-test` in the dialog to approve. Railway answers `Not Authorized`, because the token is fake. Try once with a wrong text (`vol-tes`): the dialog should show again rather than approve.
- [ ] Ask Claude: *"Run `sh railway.sh rename`."* While it waits, answer from a second terminal instead of the dialog: `opfence approve --list`, then `opfence approve <ID> --yes`.
- [ ] **The keychain test** (the one this list exists for). Ask Claude: *"Run `opfence doctor --probe --json`."* Every check should pass. In particular, the sandbox cannot reach the keychain, the approval sockets or Opfence's state folder, cannot write your Opfence config or binary, and cannot connect anywhere directly. **Send back** the JSON.
- [ ] Ask Claude to try reading the key itself: *"Run `security find-generic-password -s opfence -w`"*. It must fail. (The same command in your own terminal prints the fake token, which shows the entry exists.) **Send back** what it prints inside Claude.
- [ ] Ask Claude: *"Run `curl -sS https://example.com`."* In strict mode it is refused, because example.com is not in the catalog.
- [ ] Optional, if you have a Supabase test project and its MCP server set up in Claude Code: ask for a `select 1` through `execute_sql` (runs) and a `drop table if exists opfence_check` (Claude Code asks first, and the reason names Opfence).
- [ ] Quit Claude Code. In the same terminal, `opfence log -n 10` shows each call, its decision and outcome. `opfence log --json -n 3` shows `"credentials":["railway/…"]` on forwarded calls, which proves the real key was swapped in. `opfence log --verify` says the chain is intact.

## 4. Cursor CLI

Install it and sign in **before** starting it under Opfence, because the session keeps Cursor from changing its own config files:

```sh
curl https://cursor.com/install -fsS | bash
cursor-agent login
cd ~/opfence-check && opfence run --srt -- cursor-agent
```

- [ ] It starts and answers a simple prompt ("say hi"). Its model traffic is tunnelled, so this shows the preset's backend hosts are right. **Send back** any error, and any warning `opfence run` prints when the session ends.
- [ ] Ask it to run `sh railway.sh delete`: the dialog appears, as with Claude Code. Deny it.
- [ ] Ask it to run `opfence doctor --probe --json`. **Send back** the JSON.

## 5. Gemini CLI

```sh
npm install -g @google/gemini-cli
gemini            # sign in once, then quit
cd ~/opfence-check && opfence run --srt -- gemini
```

- [ ] It starts and answers a prompt. Note it if it complains about `~/.gemini/settings.json`. Gemini treats an empty settings file as a fatal error, and Opfence is meant to avoid creating one.
- [ ] `sh railway.sh delete` held, then denied. `opfence doctor --probe --json` inside it: **send back** the JSON.
- [ ] Optional: Codex has only been checked on Linux. If you use it, run `opfence run --srt -- codex` and repeat the two checks.

## 6. Phone approvals with ntfy.sh

- [ ] Install the **ntfy** app on your phone (App Store or Google Play).
- [ ] `opfence phone setup`. It shows a QR code: subscribe to it in the app (on iPhone, add the topic it prints as a subscription by hand). A test push arrives with a button; tap it, and setup finishes. **Send back** what it printed, but replace the topic name with `TOPIC`: anyone who knows it could answer your requests.
- [ ] In `~/opfence-check`, start `opfence run -- claude` and ask for `sh railway.sh rename`. The desktop dialog appears as before, and after about 1.5 seconds a push arrives with **Deny**, **Approve** and **Approve 10 min**. Leave the dialog and tap **Approve** on the phone: Claude gets Railway's `Not Authorized` and the dialog closes. The push should disappear from the phone (Android does this; iOS may not).
- [ ] Ask for the rename again and tap **Approve 10 min**, then ask once more: the third call runs without asking.
- [ ] Ask for `sh railway.sh delete`. The push has **Deny** only, because confirming needs the name typed. Tap Deny.
- [ ] **Send back** whether the buttons showed on your phone (iOS or Android, and the app's version), and how long the pushes took to arrive.
- [ ] `opfence phone off` when you are done, if you do not want to keep it.

## 7. Publish the documentation site

- [ ] On GitHub, open the repository's **Settings → Pages** and set **Source** to **GitHub Actions**.
- [ ] Open **Actions → site → Run workflow** on `main`. When it finishes, the site is at <https://rakeshnitb23.github.io/opfence/>.
- [ ] Check the home page, the catalog search (try `volumeDelete`) and the architecture page's diagrams, in Safari and on your phone.

## 8. Clean up

```sh
cd ~/opfence-check
opfence init --undo                 # puts the fake value back in .env
opfence secrets list                # shows the Railway key's PROVIDER/NAME
opfence secrets rm railway/NAME     # with the name it showed; removes it from the keychain
opfence trust --uninstall           # if you do not want to keep the CA
cd ~ && rm -rf ~/opfence-check
```

## What to send back

The outputs marked **Send back** above, plus one line for each step: passed, failed (with the message) or skipped. A screenshot of the macOS approval dialog and of the phone push would help with the design of both.
