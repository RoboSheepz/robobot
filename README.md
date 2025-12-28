# RoboBot — Clankslop Twitch "Bot"

A minimal Node.js Twitch bot using `tmi.js` and `dotenv`.

Setup

1. Make the `.env` file and fill in the `.env` with your credentials and default configuration:

```
TWITCH_USERNAME=your_bot's_username
TWITCH_OAUTH=oauth:your_bot's_oauth_token_

DEFAULT_ADMIN_UID=your_twitch_uid
DEFAULT_CHANNEL=channel_for_bot_to_join
DEFAULT_PREFIX=!
```

2. Install dependencies:

```powershell
npm install
```

3. Start the bot:

```powershell
npm start
```

Usage

- Type `!help` in the configured Twitch channel; the bot will respond.

Security

- Keep your `.env` file secret. Do not commit it to a public repository.

Notes

- You can generate an OAuth token for the bot at https://twitchapps.com/tmi/ or via Twitch developer tools.
