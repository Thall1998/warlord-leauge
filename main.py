import base64
import calendar
import hashlib
import hmac
import json
import logging
import os
import random
from pathlib import Path
from datetime import datetime, timezone

import discord
from discord.ext import commands, tasks
from dotenv import load_dotenv
import webserver


# Load secrets and local settings before any record data is read.
load_dotenv()
token = os.getenv("DISCORD_TOKEN")
data_secret = os.getenv("DATA_SECRET_KEY")
records_file = Path("records.json")

# Bot-wide game settings and league scoring rules.
FACTIONS = ("Devernian Empire", "Dwavern Forges", "Elven Branches", "Free Kingdoms", "Mercenary Guilds", "Nothrog Legions")
POINTS_PER_WIN = 1
WEEKLY_BOUNTY_BONUS = 2
META_KEY = "__meta__"
LEAGUE_CATEGORY_ORDER = (
    ("Most games played", "games"),
    ("Most wins", "wins"),
    ("Most unique players played", "unique_opponents"),
    ("Most losses", "losses"),
)


def _require_data_secret():
    """Return the encryption secret or stop startup with a clear error."""
    if not data_secret:
        raise RuntimeError("Missing DATA_SECRET_KEY in your .env file")

    return data_secret.encode("utf-8")


def _derive_key(salt):
    """Derive a stable encryption key from the configured secret and a file salt."""
    return hashlib.pbkdf2_hmac("sha256", _require_data_secret(), salt, 200_000, dklen=32)


def _keystream(key, nonce, length):
    """Build enough pseudo-random bytes to encrypt or decrypt the JSON payload."""
    output = bytearray()
    counter = 0

    while len(output) < length:
        output.extend(
            hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        )
        counter += 1

    return bytes(output[:length])


def _encrypt_json(data):
    """Encrypt records before writing them to disk."""
    plaintext = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    salt = os.urandom(16)
    nonce = os.urandom(16)
    key = _derive_key(salt)
    stream = _keystream(key, nonce, len(plaintext))
    ciphertext = bytes(left ^ right for left, right in zip(plaintext, stream))
    tag = hmac.new(key, salt + nonce + ciphertext, hashlib.sha256).digest()

    return {
        "version": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def _decrypt_json(envelope):
    """Verify and decrypt the saved records file."""
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    expected_tag = base64.b64decode(envelope["tag"])
    key = _derive_key(salt)
    actual_tag = hmac.new(key, salt + nonce + ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(actual_tag, expected_tag):
        raise RuntimeError("records.json could not be verified. Wrong key or changed file.")

    stream = _keystream(key, nonce, len(ciphertext))
    plaintext = bytes(left ^ right for left, right in zip(ciphertext, stream))
    return json.loads(plaintext.decode("utf-8"))


def load_records():
    """Load the encrypted record database, or start empty on first run."""
    if not records_file.exists():
        return {}

    with records_file.open("r", encoding="utf-8") as file:
        return _decrypt_json(json.load(file))


def save_records(records):
    """Persist all player and league data to the encrypted record file."""
    encrypted_records = _encrypt_json(records)

    with records_file.open("w", encoding="utf-8") as file:
        json.dump(encrypted_records, file, indent=2)


def get_player_record(player):
    """Return a player's record, creating default fields as needed."""
    player_id = str(player.id)

    if player_id not in records:
        records[player_id] = {}

    records[player_id].setdefault("wins", 0)
    records[player_id].setdefault("losses", 0)
    records[player_id].setdefault("points", 0)
    records[player_id].setdefault("faction", None)
    records[player_id].setdefault("faction_month", None)

    return records[player_id]


def current_month_key():
    """Use UTC month keys so faction timing is consistent across servers."""
    return datetime.now(timezone.utc).strftime("%Y-%m")


def current_week_key():
    """Return the ISO week key used to rotate weekly bounty factions."""
    year, week, _ = datetime.now(timezone.utc).isocalendar()
    return f"{year}-W{week:02d}"


def utc_now():
    return datetime.now(timezone.utc)


def to_iso(value):
    return value.isoformat()


def from_iso(value):
    return datetime.fromisoformat(value)


def add_one_month(value):
    """Add one calendar month while preserving the day when possible."""
    year = value.year
    month = value.month + 1

    if month == 13:
        year += 1
        month = 1

    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def format_discord_time(value):
    """Format a datetime as Discord's localized timestamp markup."""
    return f"<t:{int(value.timestamp())}:F>"


def get_meta_record():
    """Return the non-player metadata bucket inside records.json."""
    if META_KEY not in records:
        records[META_KEY] = {}

    return records[META_KEY]


def get_active_league():
    """Return the currently active league state, if one is running."""
    league = get_meta_record().get("league")

    if not league or not league.get("active"):
        return None

    return league


def get_league_player(league, player):
    """Return a player's league-only stats, creating them on faction choice."""
    player_id = str(player.id)
    players = league.setdefault("players", {})

    if player_id not in players:
        players[player_id] = {
            "wins": 0,
            "losses": 0,
            "opponents": [],
        }

    players[player_id]["joined_by_faction"] = True
    return players[player_id]


def is_joined_league_player(player_stats):
    """Return whether league stats belong to someone who joined by choosing a faction."""
    return player_stats.get("joined_by_faction", False)


def is_league_player(league, player):
    """Return whether a player has joined the active league by choosing a faction."""
    player_stats = league.get("players", {}).get(str(player.id))
    return player_stats is not None and is_joined_league_player(player_stats)


def record_league_match(winner, loser):
    """Copy a completed match into the active league standings."""
    league = get_active_league()

    if league is None:
        return False

    if not is_league_player(league, winner) or not is_league_player(league, loser):
        return False

    winner_stats = get_league_player(league, winner)
    loser_stats = get_league_player(league, loser)
    winner_id = str(winner.id)
    loser_id = str(loser.id)

    winner_stats["wins"] += 1
    loser_stats["losses"] += 1

    if loser_id not in winner_stats["opponents"]:
        winner_stats["opponents"].append(loser_id)

    if winner_id not in loser_stats["opponents"]:
        loser_stats["opponents"].append(winner_id)

    return True


def league_player_value(player_stats, category_key):
    """Calculate the ranking value for a single league award category."""
    if category_key == "games":
        return player_stats.get("wins", 0) + player_stats.get("losses", 0)

    if category_key == "unique_opponents":
        return len(player_stats.get("opponents", []))

    return player_stats.get(category_key, 0)


def get_league_winners(league):
    """Pick one unique winner for each league category."""
    winners = []
    used_player_ids = set()
    players = league.get("players", {})

    for category_name, category_key in LEAGUE_CATEGORY_ORDER:
        # Once a player wins a category, remove them from later categories.
        eligible_players = [
            (player_id, player_stats)
            for player_id, player_stats in players.items()
            if player_id not in used_player_ids and is_joined_league_player(player_stats)
        ]
        eligible_players = [
            (player_id, player_stats)
            for player_id, player_stats in eligible_players
            if league_player_value(player_stats, category_key) > 0
        ]

        if not eligible_players:
            winners.append((category_name, None, 0))
            continue

        player_id, player_stats = max(
            eligible_players,
            # Tie breakers favor activity, then wins, then unique opponents.
            key=lambda item: (
                league_player_value(item[1], category_key),
                league_player_value(item[1], "games"),
                league_player_value(item[1], "wins"),
                league_player_value(item[1], "unique_opponents"),
                league_player_value(item[1], "losses"),
                -int(item[0]),
            ),
        )
        used_player_ids.add(player_id)
        winners.append((category_name, player_id, league_player_value(player_stats, category_key)))

    return winners


def build_league_results_message(league):
    """Build the final league summary message posted to Discord."""
    started_at = from_iso(league["started_at"])
    ended_at = from_iso(league["ended_at"])
    winners = get_league_winners(league)
    result_lines = []

    for category_name, player_id, value in winners:
        if player_id is None:
            result_lines.append(f"{category_name}: No winner")
        else:
            result_lines.append(f"{category_name}: <@{player_id}> ({value})")

    return (
        "**Warlord League results**\n"
        f"League ran from {format_discord_time(started_at)} to "
        f"{format_discord_time(ended_at)}.\n"
        + "\n".join(result_lines)
    )


async def end_league(channel):
    """End the active league, archive it, save records, and post results."""
    league = get_active_league()

    if league is None:
        return False

    league["active"] = False
    league["ended_at"] = to_iso(utc_now())
    get_meta_record().setdefault("league_history", []).append(league.copy())
    save_records(records)

    await channel.send(build_league_results_message(league))
    return True


async def end_expired_league(fallback_channel=None):
    """Automatically close the active league once its end time has passed."""
    league = get_active_league()

    if league is None or utc_now() < from_iso(league["ends_at"]):
        return False

    channel = bot.get_channel(int(league["channel_id"])) or fallback_channel

    if channel is None:
        channel = await bot.fetch_channel(int(league["channel_id"]))

    return await end_league(channel)


def get_weekly_bounty():
    """Return this week's deterministic faction bounty, creating it if needed."""
    meta = get_meta_record()
    week_key = current_week_key()
    bounty = meta.get("weekly_bounty", {})

    if bounty.get("week") != week_key:
        randomizer = random.Random(week_key)
        bounty = {
            "week": week_key,
            "faction": randomizer.choice(FACTIONS),
            "bonus": WEEKLY_BOUNTY_BONUS,
        }
        meta["weekly_bounty"] = bounty
        save_records(records)

    return bounty


def normalize_faction(faction_name):
    """Match user-provided faction text to the official faction name."""
    for faction in FACTIONS:
        if faction.lower() == faction_name.lower():
            return faction

    return None


# Configure Discord logging and privileged intents.
handler = logging.FileHandler(filename="discord.log", encoding="utf-8", mode="w")
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

# Create the bot and load encrypted records before commands begin running.
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)
records = load_records()


# Discord lifecycle and background task handlers.
@bot.event
async def on_ready():
    print(f"We are ready to go {bot.user.name}")

    if not league_end_checker.is_running():
        league_end_checker.start()


@tasks.loop(minutes=30)
async def league_end_checker():
    try:
        await end_expired_league()
    except Exception:
        logging.exception("Failed to end expired league")


@league_end_checker.before_loop
async def before_league_end_checker():
    await bot.wait_until_ready()


@bot.event
async def on_member_join(member):
    await member.send(f"Welcome To The server! {member.name}")


@bot.event
async def on_message(message):
    # Ignore this bot's own messages, then let discord.py route commands.
    if message.author == bot.user:
        return

    await bot.process_commands(message)


# Player record commands.
@bot.command(name="winvs", aliases=["win", "win_vs"])
async def winvs(ctx, winner: discord.Member, loser: discord.Member):
    """Record a win, award points, and update league standings if active."""
    await end_expired_league(ctx.channel)

    if winner.id == loser.id:
        await ctx.send("A player cannot win against themselves.")
        return

    if winner.bot or loser.bot:
        await ctx.send("Bot accounts cannot be used in match records.")
        return

    winner_record = get_player_record(winner)
    loser_record = get_player_record(loser)
    bounty = get_weekly_bounty()

    winner_record["wins"] += 1
    loser_record["losses"] += 1
    winner_record["points"] += POINTS_PER_WIN
    league_match_recorded = record_league_match(winner, loser)

    bounty_message = ""
    if loser_record["faction"] == bounty["faction"]:
        # The bounty rewards defeating the faction selected for the current week.
        winner_record["points"] += bounty["bonus"]
        bounty_message = (
            f"\nWeekly bounty bonus: +{bounty['bonus']} points "
            f"for beating a member of faction {bounty['faction']}."
        )

    league_message = ""
    if get_active_league() is not None and not league_match_recorded:
        league_message = (
            "\nThis match did not count for league standings because both players "
            "must join the league by choosing a faction first."
        )

    save_records(records)

    await ctx.send(
        f"{winner.mention} beat {loser.mention}!\n"
        f"{winner.display_name}: {winner_record['wins']}W - {winner_record['losses']}L "
        f"({winner_record['points']} points)\n"
        f"{loser.display_name}: {loser_record['wins']}W - {loser_record['losses']}L"
        f"{bounty_message}"
        f"{league_message}"
    )


@bot.command()
async def record(ctx, player: discord.Member = None):
    """Show a player's all-time record, points, and current faction."""
    player = player or ctx.author
    player_record = get_player_record(player)
    wins = player_record["wins"]
    losses = player_record["losses"]
    points = player_record["points"]
    faction = player_record["faction"] or "No faction"
    total_games = wins + losses
    win_rate = 0 if total_games == 0 else round((wins / total_games) * 100, 1)

    await ctx.send(
        f"{player.mention} record: "
        f"{wins}W - {losses}L ({win_rate}% win rate), "
        f"{points} points, {faction}"
    )


@bot.command(name="beginleague", aliases=["startleague"])
@commands.has_permissions(administrator=True)
async def begin_league(ctx):
    """Start a one-month league in the current channel."""
    await end_expired_league(ctx.channel)

    if get_active_league() is not None:
        league = get_active_league()
        await ctx.send(
            "A league is already running. It ends "
            f"{format_discord_time(from_iso(league['ends_at']))}."
        )
        return

    started_at = utc_now()
    ends_at = add_one_month(started_at)
    get_meta_record()["league"] = {
        "active": True,
        "started_at": to_iso(started_at),
        "ends_at": to_iso(ends_at),
        "ended_at": None,
        "channel_id": str(ctx.channel.id),
        "guild_id": str(ctx.guild.id) if ctx.guild else None,
        "players": {},
    }
    save_records(records)

    await ctx.send(
        "**Warlord League started.**\n"
        f"It will automatically end {format_discord_time(ends_at)}.\n"
        "Categories: Most games played, most wins, most unique players played, most losses. "
        "Each category will have a different winner."
    )


@bot.command(name="leaguestatus", aliases=["league"])
async def league_status(ctx):
    """Show the current league's timing, player count, and game count."""
    await end_expired_league(ctx.channel)
    league = get_active_league()

    if league is None:
        await ctx.send("No league is currently running. Start one with `!beginleague`.")
        return

    league_players = [
        player_stats
        for player_stats in league.get("players", {}).values()
        if is_joined_league_player(player_stats)
    ]
    player_count = len(league_players)
    game_count = sum(
        player_stats.get("wins", 0)
        for player_stats in league_players
    )

    await ctx.send(
        "**Current Warlord League**\n"
        f"Started: {format_discord_time(from_iso(league['started_at']))}\n"
        f"Ends: {format_discord_time(from_iso(league['ends_at']))}\n"
        f"Players: {player_count}\n"
        f"Games recorded: {game_count}"
    )


@bot.command(name="endleague", aliases=["finishleague"])
@commands.has_permissions(administrator=True)
async def end_league_command(ctx):
    """Allow an administrator to end the current league early."""
    if get_active_league() is None:
        await ctx.send("No league is currently running. Start one with `!beginleague`.")
        return

    await end_league(ctx.channel)


@bot.command(name="factions", aliases=["faction"])
async def factions(ctx):
    """List all factions players can choose from."""
    await ctx.send("Available factions: " + ", ".join(FACTIONS))


@bot.command(name="choosefaction", aliases=["joinfaction"])
async def choose_faction(ctx, *, faction_name: str):
    """Choose a faction, or switch factions by spending current points."""
    faction = normalize_faction(faction_name)

    if faction is None:
        await ctx.send(
            "That faction does not exist. Available factions: " + ", ".join(FACTIONS)
        )
        return

    player_record = get_player_record(ctx.author)
    old_faction = player_record["faction"]
    month_key = current_month_key()

    if old_faction == faction:
        league = get_active_league()
        if league is not None and not is_league_player(league, ctx.author):
            get_league_player(league, ctx.author)
            save_records(records)
            await ctx.send(
                f"{ctx.author.mention}, you are already in faction {faction} "
                "and are now joined to the current league."
            )
            return

        await ctx.send(f"{ctx.author.mention}, you are already in faction {faction}.")
        return

    if old_faction:
        spent_points = player_record["points"]
        player_record["points"] = 0
        player_record["faction"] = faction
        player_record["faction_month"] = month_key
        league = get_active_league()
        if league is not None:
            get_league_player(league, ctx.author)
        save_records(records)
        await ctx.send(
            f"{ctx.author.mention} changed from {old_faction} to {faction} "
            f"and spent all current points ({spent_points})."
        )
        return

    player_record["faction"] = faction
    player_record["faction_month"] = month_key
    league = get_active_league()
    if league is not None:
        get_league_player(league, ctx.author)
    save_records(records)
    await ctx.send(f"{ctx.author.mention} joined faction {faction}.")


@bot.command(name="myfaction")
async def my_faction(ctx, player: discord.Member = None):
    """Show a player's faction and faction points."""
    player = player or ctx.author
    player_record = get_player_record(player)
    faction = player_record["faction"]

    if faction is None:
        await ctx.send(f"{player.mention} has not chosen a faction.")
        return

    await ctx.send(
        f"{player.mention} is in faction {faction} with "
        f"{player_record['points']} points."
    )


@bot.command(name="weeklybounty", aliases=["bounty"])
async def weekly_bounty(ctx):
    """Show the faction that grants bonus points this week."""
    bounty = get_weekly_bounty()
    await ctx.send(
        f"This week's bounty faction is {bounty['faction']} "
        f"({bounty['week']}). Beat a member of this faction to earn "
        f"+{bounty['bonus']} bonus points."
    )


@bot.command(name="choosebounty", aliases=["createbounty"])
@commands.has_permissions(administrator=True)
async def choose_bounty(ctx, *, faction_name: str):
    """Allow an administrator to choose this week's bounty faction."""
    faction = normalize_faction(faction_name)

    if faction is None:
        await ctx.send(
            "That faction does not exist. Available factions: " + ", ".join(FACTIONS)
        )
        return

    bounty = {
        "week": current_week_key(),
        "faction": faction,
        "bonus": WEEKLY_BOUNTY_BONUS,
    }
    get_meta_record()["weekly_bounty"] = bounty
    save_records(records)

    await ctx.send(
        f"This week's bounty faction is now {faction}. "
        f"Beat a member of this faction to earn +{bounty['bonus']} bonus points."
    )


@bot.command(name="factionleaderboard", aliases=["flb"])
async def faction_leaderboard(ctx):
    """Rank factions by their members' current points."""
    faction_points = {faction: 0 for faction in FACTIONS}

    for player_id, player_record in records.items():
        if player_id == META_KEY:
            continue

        faction = player_record.get("faction")
        if faction in faction_points:
            faction_points[faction] += player_record.get("points", 0)

    standings = sorted(faction_points.items(), key=lambda item: item[1], reverse=True)
    message = "\n".join(
        f"{index}. {faction}: {points} points"
        for index, (faction, points) in enumerate(standings, start=1)
    )
    await ctx.send("Faction leaderboard:\n" + message)


@bot.command(name="help")
async def bot_help(ctx):
    """Send a compact command reference."""
    await ctx.send(
        "**Warlord League commands**\n"
        "`!help` - Show this command list.\n"
        "`!winvs @winner @loser` - Record a match win. Aliases: `!win`, `!win_vs`.\n"
        "`!record [@player]` - Show wins, losses, win rate, points, and faction.\n"
        "`!faction` or `!factions` - Show all available factions.\n"
        "`!choosefaction <faction name>` - Choose or switch factions. Alias: `!joinfaction`.\n"
        "`!myfaction [@player]` - Show a player's faction and points.\n"
        "`!weeklybounty` or `!bounty` - Show this week's bounty faction.\n"
        "`!choosebounty <faction name>` - Admin: choose this week's bounty faction.\n"
        "`!factionleaderboard` or `!flb` - Show faction point totals.\n"
        "`!beginleague` - Start a one-month league.\n"
        "`!endleague` - End the current league early and post results.\n"
        "`!leaguestatus` or `!league` - Show the current league status."
    )


@winvs.error
async def winvs_error(ctx, error):
    """Give users a helpful message when win recording arguments are wrong."""
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Use this command like: `!winvs @winner @loser`")
    elif isinstance(error, commands.MemberNotFound):
        await ctx.send("I could not find one of those players. Use @mentions.")
    else:
        raise error


@record.error
async def record_error(ctx, error):
    """Handle bad player mentions for the record command."""
    if isinstance(error, commands.MemberNotFound):
        await ctx.send("I could not find that player. Use an @mention or run `!record`.")
    else:
        raise error


@choose_faction.error
async def choose_faction_error(ctx, error):
    """Explain the faction command format when the name is missing."""
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Use this command like: `!choosefaction Free Kingdoms`")
    else:
        raise error


@begin_league.error
@end_league_command.error
@choose_bounty.error
async def league_admin_error(ctx, error):
    """Explain that league management commands require administrator rights."""
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("Only server administrators can manage leagues.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Use this command like: `!choosebounty Free Kingdoms`")
    else:
        raise error

# Start the lightweight health web server, then connect the Discord bot.
webserver.keep_alive()
bot.run(token, log_handler=handler, log_level=logging.DEBUG)
