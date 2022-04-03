#!/usr/bin/env python

# WS server example

import asyncio
import json
import logging
import websockets
import datetime
import uuid
import re

import pathlib
import ssl

import glob
import os

import nest_asyncio

nest_asyncio.apply()

logging.basicConfig(level=logging.WARN, filename='day1.log')

DEFAULTSTATE = {"ID": None, "open": True, "state": "pregame", "question": -1,
                "start": datetime.datetime.now(), "end": datetime.datetime.now(),
                "players": 0, "name": "Ciphering", "automatic": False, "autograde": False, "set": "default.json"}
STATE = {}
CONSOLE = {}
PLAYERS = {}
questions = {}

qend = {}

gamefilter = re.compile(r"[^0-9]")
namefilter = re.compile(r"[^\-0-9a-zA-Z\/\. ]")
ansfilter = re.compile(r"[^\-\+0-9\/\.]")
mainfilter = re.compile(r"[<>;]")

with open("questions/precalctest.json", "r") as qs:
    defaultquestions = json.loads(qs.read())

date_handler = lambda obj: (
    obj.isoformat()
    if isinstance(obj, (datetime.datetime, datetime.date, datetime.time))
    else None
)


def state_event(GAMEID):
    return json.dumps({"type": "state", **(STATE[GAMEID])}, default=date_handler)


async def notify_state(GAMEID):
    logging.debug("Sending state")
    message = state_event(GAMEID)
    if PLAYERS[GAMEID]:  # asyncio.wait doesn't accept an empty list
        await asyncio.wait([user["websocket"].send(message) for user in PLAYERS[GAMEID].values() if user["active"]])
    if CONSOLE[GAMEID]:
        await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])


def score_event(GAMEID):  # Todo: scoring
    scores = [(PLAYERS[GAMEID][uuid]["name"], score(GAMEID, uuid), getscore(GAMEID, uuid, STATE[GAMEID]['question']))
              for uuid in PLAYERS[GAMEID].keys()]
    scores = sorted(scores, key=lambda s: s[0])
    scores = sorted(scores, key=lambda s: s[2], reverse=True)
    scores = sorted(scores, key=lambda s: s[1], reverse=True)
    return json.dumps({"type": "scores", "scores": scores}, default=date_handler)


def score(GAMEID, uuid):
    acc = 0
    for i in range(STATE[GAMEID]['question']):
        acc += getscore(GAMEID, uuid, i + 1)
    return acc


def getscore(GAMEID, uuid, qn):
    if not PLAYERS[GAMEID][uuid]["correct"][qn - 1]:
        return 0
    else:
        return (4 - PLAYERS[GAMEID][uuid]["minutes"][qn - 1]) * 4


def score_question(GAMEID, uuid, qn):
    if PLAYERS[GAMEID][uuid]["answers"][qn - 1] is None:
        logging.error("TEMP ERROR W ASNWER NONE")
        return 0
    if re.sub('[^0-9\\\.]', '', str(PLAYERS[GAMEID][uuid]["answers"][qn - 1])) not in questions[GAMEID][str(qn)][
        "answers"]:
        return 0
    if not 1 <= PLAYERS[GAMEID][uuid]["minutes"][qn - 1] <= 3:
        return 0
    else:
        return (4 - PLAYERS[GAMEID][uuid]["minutes"][qn - 1]) * 4


async def notify_scores(GAMEID):
    logging.debug("Sending scores")
    message = score_event(GAMEID)
    if PLAYERS[GAMEID]:  # asyncio.wait doesn't accept an empty list
        await asyncio.wait([PLAYERS[GAMEID][user]["websocket"].send(message) for user in
                            PLAYERS[GAMEID].keys()])  # if user["active"]])
    if CONSOLE[GAMEID]:
        await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])


async def register(websocket):
    UUID = str(uuid.uuid4())
    logging.debug(f"New user: {UUID}")
    await websocket.send(json.dumps({"type": "UUID", "UUID": UUID}, default=date_handler))
    return UUID


async def unregister(GAMEID, UUID):
    if GAMEID is None:
        return
    if UUID not in PLAYERS[GAMEID].keys():
        return
    PLAYERS[GAMEID][UUID]["active"] = False
    None


def question_event(GAMEID):
    qn = STATE[GAMEID]["question"]
    if not 1 <= qn <= len(questions[GAMEID]) + 1:
        logging.error(f"Question {qn} out of bounds!")
    if not str(qn) in questions[GAMEID].keys():
        logging.error(f"Question {qn} not in question set!")
    question = questions[GAMEID][str(qn)]["question"]
    return json.dumps({"type": "question", "question": question, "number": qn})


async def notify_question(GAMEID):
    logging.debug("Sending questions")
    message = question_event(GAMEID)
    if PLAYERS[GAMEID]:  # asyncio.wait doesn't accept an empty list
        await asyncio.wait([PLAYERS[GAMEID][user]["websocket"].send(message) for user in
                            PLAYERS[GAMEID].keys()])  # if user["active"]])
    if CONSOLE[GAMEID]:
        await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])


# Game state management

def get_questions():
    files = []
    for file in os.listdir("questions/"):
        if file.endswith(".json"):
            files += [file]

    return files


def set_questions(GAMEID, filename):
    with open("questions/" + filename, "r") as qs:
        questions[GAMEID] = json.loads(qs.read())
    logging.info(f"Set questions to {filename}")


async def start_game(GAMEID):
    STATE[GAMEID]["state"] = "pregame"
    STATE[GAMEID]["question"] = 0
    await notify_state(GAMEID)
    logging.info("Started game")


async def next_question(GAMEID):
    STATE[GAMEID]["question"] += 1
    STATE[GAMEID]["start"] = datetime.datetime.now() + datetime.timedelta(seconds=6)
    STATE[GAMEID]["end"] = datetime.datetime.now() + datetime.timedelta(minutes=3, seconds=6)
    await countdown(GAMEID)
    asyncio.get_running_loop().call_later(6, asyncio.create_task, open_question(GAMEID))
    qend[GAMEID] = asyncio.get_running_loop().call_later(189, asyncio.create_task, end_question(GAMEID))
    # question
    # end


async def countdown(GAMEID):
    STATE[GAMEID]["state"] = "countdown"
    await notify_state(GAMEID)


async def open_question(GAMEID):
    STATE[GAMEID]["state"] = "question"
    await notify_question(GAMEID)
    await notify_state(GAMEID)


async def end_question(GAMEID):
    logging.info("QUESTION HAS ENDED")
    STATE[GAMEID]["state"] = "end"
    await notify_scores(GAMEID)
    await notify_state(GAMEID)
    if STATE[GAMEID]['question'] >= len(questions[GAMEID]):
        await end_game(GAMEID)
    elif STATE[GAMEID]['automatic']:
        asyncio.get_running_loop().call_later(10, asyncio.create_task, next_question(GAMEID))


async def end_game(GAMEID):
    STATE[GAMEID]["state"] = "endgame"
    await notify_state(GAMEID)
    logging.info("Ended game")
    # End game!! #errrorosr implement


async def reset_game(GAMEID):
    STATE[GAMEID]["state"] = "pregame"
    STATE[GAMEID]["question"] = -1
    await notify_state(GAMEID)
    logging.info("Reset game")


def minute(GAMEID):
    min = (STATE[GAMEID]["end"] - datetime.datetime.now()).seconds
    min = 60 if 0 <= min <= 5 else min + 55
    return min // 60


def everyone_done(GAMEID):
    qn = STATE[GAMEID]["question"]
    if not 0 <= qn - 1 <= len(questions[GAMEID]):
        logging.error(f"Question {qn} out of bounds!")
    for player in PLAYERS[GAMEID].values():
        if not 0 <= qn - 1 <= len(player["answers"]):
            logging.error(f"Question {qn} out of bounds of answer array!")
        if player["answers"][qn - 1] is None and player["active"]:
            return False
    return True


async def check_for_done(GAMEID):
    if everyone_done(GAMEID):
        if qend[GAMEID] is not None:
            qend[GAMEID].cancel()
        await end_question(GAMEID)


async def counter(websocket, path):
    global CONSOLE

    # register(websocket) assigns a UUID and
    UUID = await register(websocket)
    ISCONSOLE = False
    ISEDITOR = False
    GAMEID = None

    try:
        # await websocket.send(state_event(GAMEID))
        async for message in websocket:
            if GAMEID is not None:
                subtime = minute(GAMEID)
            else:
                subtime = 0

            data = json.loads(mainfilter.sub('', message))

            if data["action"] == 'set_uuid':
                UUID = data["UUID"]
                # console rejoin support??
                for id in STATE.keys():
                    if UUID in PLAYERS[id].keys():
                        GAMEID = id
                        PLAYERS[GAMEID][UUID]["websocket"] = websocket
                        await notify_state(GAMEID)
                        logging.debug("sending player list")
                        message = json.dumps({"type": "players", "players": PLAYERS[GAMEID]},
                                             default=lambda o: '<not serializable>')
                        await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])
                        break
                    elif UUID in CONSOLE[id]:
                        continue  # fseogoin
                        GAMEID = id
                        CONSOLE[GAMEID]
                        await websocket.send(state_event(GAMEID))
                        ISCONSOLE = True
                        if STATE[GAMEID]["open"]:
                            logging.debug("sending player list")
                            message = json.dumps({"type": "players", "players": PLAYERS[GAMEID]},
                                                 default=lambda o: '<not serializable>')
                            await websocket.send(message)
                        break



            elif data["action"] == "create_game":
                intid = None
                while intid is None or intid in STATE.keys():
                    hexUUID = str(uuid.uuid4())[:8]
                    intid = str(int(hexUUID, 16))[:6]

                STATE[intid] = DEFAULTSTATE.copy()
                STATE[intid]["ID"] = intid
                CONSOLE[intid] = [websocket]
                PLAYERS[intid] = {}
                questions[intid] = defaultquestions

                GAMEID = intid
                logging.info(f"{UUID}: Attached to console")
                await websocket.send(state_event(GAMEID))
                ISCONSOLE = True

            elif data["action"] == "connect_game":
                if data["gameid"] in STATE.keys():
                    GAMEID = gamefilter.sub('', data["gameid"])
                    CONSOLE[data["gameid"]] += [websocket]
                    logging.info(f"{UUID}: Attached to console")
                    await websocket.send(state_event(GAMEID))
                    ISCONSOLE = True
                    if STATE[GAMEID]["open"]:
                        logging.debug("sending player list")
                        message = json.dumps({"type": "players", "players": PLAYERS[GAMEID]},
                                             default=lambda o: '<not serializable>')
                        await websocket.send(message)
                else:
                    await websocket.send(json.dumps({"type": "error", "error": "Game does not exist"}))


            elif data["action"] == "set_config":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                if "automatic" in data.keys():
                    STATE[GAMEID]["automatic"] = data["automatic"]
                if "autograde" in data.keys():
                    STATE[GAMEID]["autograde"] = data["autograde"]
                if "set" in data.keys():
                    STATE[GAMEID]["set"] = data["set"]
                    set_questions(GAMEID, data['set'])
                await notify_state(GAMEID)


            elif data["action"] == "start_game":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                if "automatic" in data.keys():
                    STATE[GAMEID]["automatic"] = data["automatic"]
                if "autograde" in data.keys():
                    STATE[GAMEID]["autograde"] = data["autograde"]
                await start_game(GAMEID)

            elif data["action"] == "next_question":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                await next_question(GAMEID)

            elif data["action"] == "end_game":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                await end_game(GAMEID)


            elif data["action"] == "reset_game":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                await reset_game(GAMEID)

            elif data["action"] == "get_questions":
                await websocket.send(json.dumps({"type": "sets", "sets": get_questions()}))

            elif data["action"] == "set_questions":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                set_questions(GAMEID, data["filename"])

            elif data["action"] == "remove_player":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                logging.warning("Removing player" + data["player"])
                try:
                    if data["player"] in PLAYERS[GAMEID].keys():
                        await PLAYERS[GAMEID][data["player"]]["websocket"].send(
                            json.dumps({"type": "error", "error": "disconnected"}))
                        del PLAYERS[GAMEID][data["player"]]
                except:
                    None

                message = json.dumps({"type": "players", "players": PLAYERS[GAMEID]},
                                     default=lambda o: '<not serializable>')
                await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])

            # todo
            elif data["action"] == "softremove_player":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                logging.warning("Removing player" + data["player"])
                try:
                    if data["player"] in PLAYERS[GAMEID].keys():
                        await PLAYERS[GAMEID][data["player"]]["websocket"].send(
                            json.dumps({"type": "error", "error": "disconnected"}))
                        PLAYERS[GAMEID][data["player"]]["active"] = False
                except:
                    None

                message = json.dumps({"type": "players", "players": PLAYERS[GAMEID]},
                                     default=lambda o: '<not serializable>')
                await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])

            elif data["action"] == "accept_answer":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                PLAYERS[GAMEID][data["player"]]["correct"][int(data["question"]) - 1] = True
                message = json.dumps({"type": "players", "players": PLAYERS[GAMEID]},
                                     default=lambda o: '<not serializable>')
                await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])
                await notify_scores(GAMEID)

            elif data["action"] == "reject_answer":
                if not ISCONSOLE:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not console"}))
                    continue
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue

                PLAYERS[GAMEID][data["player"]]["correct"][int(data["question"]) - 1] = False
                message = json.dumps({"type": "players", "players": PLAYERS[GAMEID]},
                                     default=lambda o: '<not serializable>')
                await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])
                await notify_scores(GAMEID)




            elif data["action"] == "find_game":
                if data["gameid"] in STATE.keys():
                    logging.info(f"{UUID}: looking for game")
                    await websocket.send(state_event(gamefilter.sub('', data["gameid"])))
                    GAMEID = gamefilter.sub('', data["gameid"])
                else:
                    await websocket.send(json.dumps({"type": "error", "error": "Game does not exist"}))


            elif data["action"] == "join_game":
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue
                if not STATE[GAMEID]["open"]:
                    await websocket.send(json.dumps({"type": "error", "error": "Game is closed..?"}))
                    continue

                logging.info(data)
                if UUID not in PLAYERS[GAMEID].keys():
                    PLAYERS[GAMEID][UUID] = {"websocket": websocket, "answers": [None] * 12, "minutes": [-1] * 12,
                                             "correct": [None] * 12, \
                                             "active": True, "name": namefilter.sub('', data["name"])}
                else:
                    PLAYERS[GAMEID][UUID]["active"] = True
                STATE[GAMEID]["players"] = len(PLAYERS[GAMEID])  # TODO fix num players
                await notify_state(GAMEID)
                message = json.dumps({"type": "players", "players": PLAYERS[GAMEID]},
                                     default=lambda o: '<not serializable>')
                await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])
                # await notify_state()



            elif data["action"] == "answer":
                if GAMEID is None:
                    await websocket.send(json.dumps({"type": "error", "error": "Not connected to a game"}))
                    continue
                if not STATE[GAMEID]["open"]:
                    await websocket.send(json.dumps({"type": "error", "error": "Game is closed"}))
                    continue
                if UUID not in PLAYERS[GAMEID].keys():
                    logging.error(f"{UUID}: submitted answer without registering as player")
                    continue
                if not STATE[GAMEID]["state"] == "question":
                    logging.error(f"{UUID}: submitted answer without active game")
                    continue
                elif PLAYERS[GAMEID][UUID]["answers"][STATE[GAMEID]["question"] - 1] is not None:
                    logging.info(f"{UUID}: submitted a second answer")
                    if STATE[GAMEID]["autograde"]:
                        PLAYERS[GAMEID][UUID]["correct"][qn] = False
                    continue

                if subtime < 1:
                    logging.error(f"{UUID}: submitted early")
                    if STATE[GAMEID]["autograde"]:
                        PLAYERS[GAMEID][UUID]["correct"][qn] = False
                    continue
                if subtime > 3:
                    logging.info(f"{UUID}: submitted late")
                    if STATE[GAMEID]["autograde"]:
                        PLAYERS[GAMEID][UUID]["correct"][qn] = False
                    subtime = 0

                qn = STATE[GAMEID]["question"] - 1
                PLAYERS[GAMEID][UUID]["answers"][qn] = ansfilter.sub('', data["answer"])
                PLAYERS[GAMEID][UUID]["minutes"][qn] = 4 - subtime
                if STATE[GAMEID]["autograde"]:
                    PLAYERS[GAMEID][UUID]["correct"][qn] = (score_question(GAMEID, UUID, qn + 1) != 0)

                message = json.dumps({"type": "players", "players": PLAYERS[GAMEID]},
                                     default=lambda o: '<not serializable>')
                await asyncio.wait([c.send(message) for c in CONSOLE[GAMEID]])
                await check_for_done(GAMEID)


            elif data['action'] == "start_editor":
                ISEDITOR = True

            elif data['action'] == "read_set_data":
                if not ISEDITOR:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not an editor"}))
                    continue
                if os.path.exists("questions/" + data['file']):
                    with open("questions/" + data['file'], "r+") as file:
                        await websocket.send(json.dumps({"type": "data", "data": file.read()}))
                else:
                    with open("template.json", "r+") as file:
                        await websocket.send(json.dumps({"type": "data", "data": file.read()}))

            elif data['action'] == "write_set_data":
                if not ISEDITOR:
                    await websocket.send(json.dumps({"type": "error", "error": "You are not an editor"}))
                    continue
                logging.debug(data['data'])
                with open("questions/" + data['file'], "w+") as file:
                    file.write(data["data"])

            else:
                logging.error("unsupported event: %s", data)


    finally:
        await unregister(GAMEID, UUID)


ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
crtfile = pathlib.Path('server.crt')
keyfile = pathlib.Path('server.pem')
ssl_context.load_cert_chain(crtfile, keyfile=keyfile)

# start_server = websockets.serve(counter, "0.0.0.0", 8765, ssl=ssl_context)
start_server = websockets.serve(counter, "0.0.0.0", 8765)

asyncio.get_event_loop().run_until_complete(start_server)