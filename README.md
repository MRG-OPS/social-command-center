# Social Command Center

Private social media dashboard for Maria Rocha Group and Mi Casa, Iowa.

Everything on this site is encrypted. The page only opens with the team login
(marketing@mariarochagroup.com plus the shared password). Ask the marketing team for the password.

## Files
- `index.html`: sign-in page
- `app.enc.json`, `data.enc.json`: the encrypted dashboard and data
- `vault.json`: encrypted keys for the team login
- `tools/`: scripts for refreshing data and managing the login

## Refreshing data
`python3 tools/encrypt_data.py path/to/data.json` writes a new `data.enc.json`. Plain data is never committed.

## Changing the password
`python3 tools/remove_user.py marketing@mariarochagroup.com` and then `python3 tools/add_user.py marketing@mariarochagroup.com`.
Run `tools/rotate_keys.py` if the old password should stop working for data that was already published.
