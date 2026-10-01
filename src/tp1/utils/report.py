from tp1.utils.capture import Capture, Summary
from tp1.utils.logger import logger
import numpy as np
import matplotlib.pyplot as pylab
import json

class Report:
    def __init__(self, capture: Capture, filename: str, summary: Summary):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = []
        self.graph = pylab.pyplot()
        self.json = {}

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph

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
        Attend un array
        """
        if param == "graph":
            # TODO: generate graph
            x,y = []
            """
            Parse le summary pour récuperer les données
            """
            for i in range(0,len(self.summary),2):
                x.append(self.summary[i])
                y.append(int(self.summary[i+1]))
            graph = pylab.bar(x,y)
            self.graph = graph
        elif param == "array":
            # TODO: generate array
            array = [[protocol, count]]
            """
            Parse le summary pour récuperer les données
            """
            for i in range(0,len(self.summary),2):
                array.append([self.summary[i],int(self.summary[i+1])])

            self.array = array

    def generate_json(self) -> None:
        json_output = {"protocols":{},"attacks": [],"flag": str}
        for couple in self.summary.protocols:
            json_output["protocols"].append({"protocol": couple[0], "count": int(couple[1])})
        for attacks in self.summary.attacks:
            json_output["attacks"].append({"type": attacks["type"], "attacker":attacks["attacker"]})
        json_output["flag"] = self.summary.flag
        self.json = json.dumps(json_output)
