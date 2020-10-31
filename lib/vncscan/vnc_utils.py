from time import sleep

def run_ducky(vnc, ducky_script):

    with open(ducky_script) as f:
        script = f.read()

    instr_list = getInstructions(script)

    for instr in instr_list:
        if instr[0] == 'REM':
            continue
        elif instr[0] == 'DELAY':
            sleep(int(instr[1])/1000)
        elif instr[0] == 'STRING':
            vnc.typeString(instr[1])
        else:
            keys = instr[0].split('-')
            if instr[1] != None:
                keys.append(instr[1])
            vnc.typeSpecial(tuple(keys))


def getInstructions(strData):
    #Instrution dic
    instruntions_dic = {"WINDOWS","GUI","CONTROL","CTRL","ALT","SHIFT","CTRL-ALT","CTRL-SHIFT","COMMAND-OPTION","ALT-SHIFT","ALT-TAB","DELAY","DEFAULT-DELAY","DEFAULTDELAY","DEFAULT_DELAY","ENTER","REPEAT","REM","STRING","ESCAPE","DEL","BREAK","DOWN","UP","DOWNARROW","UPARROW","LEFTARROW","RIGHTARROW","MENU","PLAY","PAUSE","STOP","MUTE","VULUMEUP","VOLUMEDOWN","SCROLLLOCK","NUMLOCK","CAPSLOCK"}

    instructions = []; last_ins = ""; delay = -1; current_ins = []
    # Handle REPEAT and DEFAULT-DELAY instructions
    for line in strData.split("\n"):
        line = line.rstrip()
        # Ignore empty lines
        if line != '\n' and line != '':
            # Ignore the comments
            if not line.startswith("//"):
                # Check if the command has any arguments
                if " " in line:
                    current_ins = line.strip().split(" ", 1)
                    if current_ins[0] not in instruntions_dic:
                        print("Instrution not found : %s" % line.strip())
                        continue
                else:
                    if line.strip() in instruntions_dic:
                        current_ins = [line.strip(), None]
                        #instructions.append(current_ins)
                    else:
                        print("Instrution not found : %s" % line.strip())
                        continue

                if current_ins[0] == "REPEAT":
                    for i in range(int(current_ins[1])):
                        if last_ins != "":
                            instructions.append(last_ins)
                            if delay != -1:
                                instructions.append(["DELAY", delay])
                        else:
                            raise Exception("ERROR: REPEAT can't be the first instruction")
                elif current_ins[0] == "DEFAULT_DELAY" or current_ins[0] == "DEFAULTDELAY" or current_ins[0] == "DEFAULT-DELAY":
                    delay = int(current_ins[1])
                else:
                    instructions.append(current_ins)
                    if delay != -1:
                        instructions.append(["DELAY", delay])
                    # Keep the previous instruction in case we need to repeat it
                    last_ins = current_ins
    if delay != -1:
        instructions.pop()

    return instructions
