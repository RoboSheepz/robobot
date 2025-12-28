# RoboBot — Minimal Twitch Hello Bot

A minimal Node.js Twitch bot using `tmi.js` and `dotenv`.

Setup

1. Fill in the `.env` file with your Twitch credentials:

```
TWITCH_USERNAME=your_bot_username
TWITCH_OAUTH=oauth:your_oauth_token_here
TWITCH_CHANNEL=channel_name
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

- Type `!ping` in the configured Twitch channel; the bot will respond.

Security

- Keep your `.env` file secret. Do not commit it to a public repository.

Notes

- You can generate an OAuth token for the bot at https://twitchapps.com/tmi/ or via Twitch developer tools.
