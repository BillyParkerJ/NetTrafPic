import PIL.Image
import scapy.packet
from scapy.all import *
from scapy.layers.inet import IP


class NetTrafPic:

    def __init__(self):
        self.pHeight = 0
        self.pWidth = 0
        self.totalPicSize = 0
        self.filter = ""


    #region UserInput
    def uInput(self):
        inputU:str

        needsInput = True
        while(needsInput):
            print("1: Info and Help\n"
                 "2: Set Imagesize\n"
                 "3. Create New Image\n"
                 "3. Set a Filter\n"
                 "5/Q: Quit \n")

            inputU = input()
            if inputU in [1,"1"]:
                print("---\n "
                      "1 - Info\n "
                      "2 - Help")
                infoHelpInput = input()

                if infoHelpInput == "1":
                    self.printInfo()
                    input()
                elif infoHelpInput == "2":
                    self.printHelp()
                    input()
                else:
                    print("\n--- Invalid Input! ---\n")

            elif inputU == "2":
                newW = input("Width: ")
                newH = input("Height: ")

                #region Set new Heigth and Width
                if newW.isnumeric():
                    self.pWidth =  int(newW)
                else:
                    print("Invalid Width!\n")

                if newH.isnumeric():
                    self.pHeight =  int(newH)
                else:
                    print("Invalid Height!\n")
                #endregion

            elif inputU == "3":
                if self.pHeight == 0:
                    self.pHeight = 200
                if self.pWidth == 0:
                    self.pWidth = 200

                colorList = self.getPackets()
                if len(colorList) > 0:

                    self.createPic(self.pHeight, self.pWidth, colorList)

                    print("\nPic created\n-----------------------------------------------------------------------------------")
                else:
                    print("--- Failed to create a Picture! ---")
                continue

            elif inputU == "4":
                self.filter = input("Filter: ")

            elif inputU in ["Q","q","5"]:
                needsInput = False

            else:
                print("Invalid Input! \n")
                continue

    def printInfo(self):
        print("\n------------------------------------------------------------"
              "\n This is a small script to turn your Adpaters Netowrk-traffic into a Picture! \n"
              "\n It does so by applying the Packet Source,Destination and size as RGB Values. "
              "\n------------------------------------------------------------")


    def printHelp(self):
        print("1. Help ==> Choose between Info and Help \n"
              "2. Set Imagesize ==> Set the width and height of the image to be generated."
              "The default is 200 x 200 (40000 packets) \n"
              "3.Generate Image ==> The script will capture any packets going through your network-adapter and "
              "generate an image out of them \n"
              "4. Set Filter ==> Sets the Filter to be used by the capture-process. Default is no filter\n"
              "The Syntax is the Berkeley Packet Filter Syntax (BPF), which can be found here: https://biot.com/capstats/bpf.html \n"
              "5. Quit ==> Exits the script \n")

    #endregion

    #region Getting the Packets
    def getPackets(self):
        # start listening to Network

        self.totalPicSize = (self.pHeight * self.pWidth)
        print(f"Listening over Interface: "
              f"\nName: {conf.iface.name}"
              f"\nDescr: {conf.iface.description}\n"
              f" --- --- --- --- --- --- --- \n")

        pktList = [scapy.packet.Packet]
        pktList.clear()
        pktNum = 0
        rgbList = []


        while len(pktList) < self.totalPicSize:
            packet = sniff(iface=conf.iface, count= 100, filter=self.filter)
            if packet is not None  and len(packet)>0 and packet[0] is not None:
                pktList.append(packet[0])
                pktNum+=1

                if self.totalPicSize > 1000000:
                    if len(pktList) % 100 == 0:
                        print(f"{str((pktNum / self.totalPicSize)*100)[0:5]}% collected \b")

                        if len(pktList) % 1000 == 0:
                            print(f"{len(pktList)}/{self.totalPicSize} Packets")

                elif len(pktList) % 10 == 0:
                    print(f"{str((pktNum / self.totalPicSize)*100)[0:5]}% collected \b")

        if len(pktList) > 0:
            for pkt in pktList:
                if IP in pkt:
                    # src = R | dst = G | size = B
                    Rval:int = int(pkt[IP].src[0:2].replace('.',''))
                    Gval:int = int(pkt[IP].dst[0:2].replace('.',''))
                    Bval:int = int(pkt[IP].len)
                    rgbList.append([Rval, Gval, Bval])
                else:
                    rgbList.append([255,255,255])
        else:
            print("Not enough packets collected!\n")
            return []

        return rgbList
    #endregion


    def createPic(self, pHeigth:int, pWidth:int, packList:list[list[int,int,int]],picMode:str = "RGBX"):
        netIMG = PIL.Image.new(picMode, [pHeigth, pWidth])

        pixNum =0
        for y in range(0,pHeigth): #Height
            for x in range(0, pWidth): #Length
                pixel:tuple = tuple(packList[pixNum])
                netIMG.putpixel([y,x],pixel)
                pixNum += 1
        netIMG.show()

if __name__ == '__main__':
    net = NetTrafPic()
    net.uInput()
    print("------------Terminated------------")


