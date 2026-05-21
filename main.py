import base64
import hashlib
import hmac
import json
import logging
import os
import random
from pathlib import Path
from datetime import datetime, timezone

import discord
from discord.ext import commands
from dotenv import load_dotenv
import webserver


# discord token and load environment file
load_dotenv()
token = os.getenv("DISCORD_TOKEN")
data_secret = os.getenv("DATA_SECRET_KEY")
records_file = Path("records.json")

FACTIONS = ("Devernian Empire", "Dwavern Forges", "Elven Branches", "Free Kingdoms", "Mercenary Guilds", "Nothrog Legions")
POINTS_PER_WIN = 1
WEEKLY_BOUNTY_BONUS = 2
META_KEY = "__meta__"


def _require_data_secret():
    if not data_secret:
        raise RuntimeError("Missing DATA_SECRET_KEY in your .env file")

    return data_secret.encode("utf-8")


def _derive_key(salt):
    return hashlib.pbkdf2_hmac("sha256", _require_data_secret(), salt, 200_000, dklen=32)


def _keystream(key, nonce, length):
    output = bytearray()
    counter = 0

    while len(output) < length:
        output.extend(
            hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        )
        counter += 1

    return bytes(output[:length])


def _encrypt_json(data):
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
    if not records_file.exists():
        return {}

    with records_file.open("r", encoding="utf-8") as file:
        return _decrypt_json(json.load(file))


def save_records(records):
    encrypted_records = _encrypt_json(records)

    with records_file.open("w", encoding="utf-8") as file:
        json.dump(encrypted_records, file, indent=2)


def get_player_record(player):
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
    return datetime.now(timezone.utc).strftime("%Y-%m")


def current_week_key():
    year, week, _ = datetime.now(timezone.utc).isocalendar()
    return f"{year}-W{week:02d}"


def get_meta_record():
    if META_KEY not in records:
        records[META_KEY] = {}

    return records[META_KEY]


def get_weekly_bounty():
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
    for faction in FACTIONS:
        if faction.lower() == faction_name.lower():
            return faction

    return None


# logging handler
handler = logging.FileHandler(filename="discord.log", encoding="utf-8", mode="w")
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

# command prefix
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)
records = load_records()


# bot event
@bot.event
async def on_ready():
    print(f"We are ready to go {bot.user.name}")


@bot.event
async def on_member_join(member):
    await member.send(f"Welcome To The server! {member.name}")


@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    await bot.process_commands(message)


# winner function
@bot.command(name="winvs", aliases=["win", "win_vs"])
async def winvs(ctx, winner: discord.Member, loser: discord.Member):
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

    bounty_message = ""
    if loser_record["faction"] == bounty["faction"]:
        winner_record["points"] += bounty["bonus"]
        bounty_message = (
            f"\nWeekly bounty bonus: +{bounty['bonus']} points "
            f"for beating a member of faction {bounty['faction']}."
        )

    save_records(records)

    await ctx.send(
        f"{winner.mention} beat {loser.mention}!\n"
        f"{winner.display_name}: {winner_record['wins']}W - {winner_record['losses']}L "
        f"({winner_record['points']} points)\n"
        f"{loser.display_name}: {loser_record['wins']}W - {loser_record['losses']}L"
        f"{bounty_message}"
    )


@bot.command()
async def record(ctx, player: discord.Member = None):
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


@bot.command(name="factions", aliases=["faction"])
async def factions(ctx):
    await ctx.send("Available factions: " + ", ".join(FACTIONS))


@bot.command(name="choosefaction", aliases=["joinfaction"])
async def choose_faction(ctx, *, faction_name: str):
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
        await ctx.send(f"{ctx.author.mention}, you are already in faction {faction}.")
        return

    if old_faction:
        spent_points = player_record["points"]
        player_record["points"] = 0
        player_record["faction"] = faction
        player_record["faction_month"] = month_key
        save_records(records)
        await ctx.send(
            f"{ctx.author.mention} changed from {old_faction} to {faction} "
            f"and spent all current points ({spent_points})."
        )
        return

    player_record["faction"] = faction
    player_record["faction_month"] = month_key
    save_records(records)
    await ctx.send(f"{ctx.author.mention} joined faction {faction}.")


@bot.command(name="myfaction")
async def my_faction(ctx, player: discord.Member = None):
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
    bounty = get_weekly_bounty()
    await ctx.send(
        f"This week's bounty faction is {bounty['faction']} "
        f"({bounty['week']}). Beat a member of this faction to earn "
        f"+{bounty['bonus']} bonus points."
    )


@bot.command(name="factionleaderboard", aliases=["flb"])
async def faction_leaderboard(ctx):
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
    await ctx.send(
        "**Warlord League commands**\n"
        "`!help` - Show this command list.\n"
        "`!winvs @winner @loser` - Record a match win. Aliases: `!win`, `!win_vs`.\n"
        "`!record [@player]` - Show wins, losses, win rate, points, and faction.\n"
        "`!faction` or `!factions` - Show all available factions.\n"
        "`!choosefaction <faction name>` - Choose or switch factions. Alias: `!joinfaction`.\n"
        "`!myfaction [@player]` - Show a player's faction and points.\n"
        "`!weeklybounty` or `!bounty` - Show this week's bounty faction.\n"
        "`!factionleaderboard` or `!flb` - Show faction point totals."
    )


@winvs.error
async def winvs_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Use this command like: `!winvs @winner @loser`")
    elif isinstance(error, commands.MemberNotFound):
        await ctx.send("I could not find one of those players. Use @mentions.")
    else:
        raise error


@record.error
async def record_error(ctx, error):
    if isinstance(error, commands.MemberNotFound):
        await ctx.send("I could not find that player. Use an @mention or run `!record`.")
    else:
        raise error


@choose_faction.error
async def choose_faction_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Use this command like: `!choosefaction Ash`")
    else:
        raise error

webserver.keep_alive()
bot.run(token, log_handler=handler, log_level=logging.DEBUG)
