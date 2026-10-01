from reportlab.platypus import Table

from tp1.utils.capture import Capture, Summary
#from tp1.utils.logger import logger
import matplotlib.pyplot as pylab
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
import json

class Report:
    def __init__(self, capture: Capture, filename: str, summary: Summary):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = []
        self.graph = pylab
        self.json = {}

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        pdf = canvas.Canvas(self.filename)
        pdf.setTitle(self.title)
        content = ""
        content += json.dumps(self.summary.to_dict())
        t = Table(self.array)

        pdf.drawString(100,400,content)
        #content += self.title
        #content += self.summary

        return content

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        final_content = self.concat_report()
        with open(self.filename, "w") as report:
            report.write(final_content)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":

            x,y = []
            """ 
            Parse le summary pour récuperer les données
            """
            for i in json.dumps(self.summary.to_dict()["protocols"]):
                print(i)
                x.append(i[0])
                y.append(int(i[1]))
            graph = pylab.bar(x,y)
            #logger("graph output",graph)
            self.graph = graph
        elif param == "array":
            array = [["protocol", "count"]]
            """
            Parse le summary pour récuperer les données
            """
            for i in self.summary.to_dict()["protocols"]:
                array.append([i[0],i[1]])
            #logger("array output",array)
            self.array = array

    def generate_json(self) -> None:
        dictionary = self.summary.to_dict()
        json_output = {"protocols": dictionary["protocols"],
                       "attacks": dictionary["attacks"],
                       "flag": dictionary["flag"]}
        self.json = json.dumps(json_output)
