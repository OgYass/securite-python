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
        self.graph = pylab.plot()
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
        """
        if param == "graph":
            x,y = []
            """
            Parse le summary pour récuperer les données
            """
            for i in self.summary.protocols:
                x.append(i[0])
                y.append(int(i[1]))
            graph = pylab.bar(x,y)
            logger("graph output",graph)
            self.graph = graph
        elif param == "array":
            array = [[protocol, count]]
            """
            Parse le summary pour récuperer les données
            """
            for i in self.summary.protocols:
                array.append(i[0],int(i[1]))
            logger("array output",array)
            self.array = array

    def generate_json(self) -> None:
        json_output = {"protocols":{},"attacks": [],"flag": str}
        for couple in self.summary.protocols:
            json_output["protocols"].append({couple[0]: int(couple[1])})
        for attacks in self.summary.attacks:
            json_output["attacks"].append({"type": attacks["type"], "attacker":attacks["attacker"]})
        json_output["flag"] = self.summary.flag
        self.json = json.dumps(json_output)
