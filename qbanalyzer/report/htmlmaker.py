__G__ = "(G)bd249ce4"

from ..logger.logger import logstring,verbose,verbose_flag
from ..mics.qprogressbar import progressbar
from yara import compile
from jinja2 import Template
from platform import platform
from datetime import datetime
from sys import modules
from os import mkdir, path

#needs cheching..

class HtmlMaker:
    @verbose(verbose_flag)
    @progressbar(True,"Starting HtmlMaker")
    def __init__(self,qbimage):
        self.templates = path.abspath(path.join(path.dirname( __file__ ),'templates'))
        if not self.templates.endswith(path.sep): self.templates = self.templates+path.sep
        if not path.isdir(self.templates): mkdir(self.templates)
        self.d = '(QBAnalyzer∞ proudly uses/depends on Docker, Python3, Bootstrap, Javascript, D3.js, JSON, Html, Sqlite3, Wikipedia, Linux Documentation, MacOS Documentation, Microsoft Docs, software77, Android Documentation, MITRE ATT&CK™, sc0ty, hexacorn, PEiD, 7z, Cisco Umbrella, a lot of researches and awesome python packeges ..) If i missed a reference/dependency, please let me know!'
        self.template = self.templates + "template.html"
        self.qbi = qbimage
        self.getmoudles()

    @verbose(verbose_flag)
    def getmoudles(self):
        x = [x.split(".")[0] for x in modules.keys() if not x.startswith("_")]
        self.d = '(QBAnalyzer∞ proudly uses/depends on Docker, Python3, Bootstrap, Javascript, D3.js, JSON, Html, Sqlite3, Wikipedia, Linux Documentation, MacOS Documentation, Microsoft Docs, software77, Android Documentation, MITRE ATT&CK™, sc0ty, hexacorn, PEiD, 7z, Cisco Umbrella, a lot of researches and awesome python packeges such as {} ..) If i missed a reference/dependency, please let me know!'.format(', '.join(list(set(x))))
        return

    @verbose(verbose_flag)
    def addtextarea(self):
        return """<div class=textareawrapper><textarea rows="1"></textarea></div>"""

    @verbose(verbose_flag)
    @progressbar(True,"Making yara table")
    def makeyaratable(self,data):
        table = ""
        if len(data) > 0:
            table += self.makelisttableforyara(data,["Offset","Rule","String","Parsed","Condition"],None,True)
        return table

    @verbose(verbose_flag)
    def makeimagetablebase64(self,data,header,exclude=None,textarea=None):
        temp = """
        <div class="tablewrapper">
        <table>
            <thead>
                <tr>
                    <th colspan="1">{{ header }}</th>
                </tr>
            </thead>
            <tbody>
                   <tr>
                        <td><img src="{{ data }}" /></td>
                    </tr>
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.addtextarea()
        result = Template(temp).render(header=header,data=data)
        return result

    @verbose(verbose_flag)
    def makealistsettablenew1(self,data,headers,exclude=None,textarea=None,_safe=None):
        temp = """
        <div class="tablewrapper">
        <table>
            <thead>
                <tr>
                    {% for header in headers %}
                        <th>{{ header }}</th>
                    {% endfor %}
                </tr>
            </thead>
            <tbody>
                {% for item in data %}
                    <tr>
                    {% for header in headers %}
                        {% if header in item %}
                            {% if _safe == None %}
                                <td>{{item[header]|e}}</td>
                            {% else %}
                                <td>{{item[header]|safe}}</td>
                            {% endif %}
                        {% else %}
                            <td></td>
                        {% endif %}
                    {% endfor %}
                    </tr>
                {% endfor %}
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.addtextarea()
        result = Template(temp).render(headers=headers,data=data,_safe=_safe)
        return result

    @verbose(verbose_flag)
    def makealistsettablenew2(self,data,headers,exclude=None,textarea=None,_safe=None):
        temp = """
        <div class="tablewrapper">
        <table>
            <thead>
                <tr>
                    {% for header in headers %}
                        <th>{{ header }}</th>
                    {% endfor %}
                </tr>
            </thead>
            <tbody>
                {% for key, value in data.items() %}
                   {% if key not in exclude%}
                       <tr>
                       {% if _safe == None %}
                            <td>{{key|e}}</td>
                            <td>{{value|e}}</td>
                            
                        {% else %}
                            <td>{{key|safe}}</td>
                            <td>{{value|safe}}</td>
                        {% endif %}
                    </tr>
                   {% endif %}
                {% endfor %}
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.addtextarea()
        result = Template(temp).render(headers=headers,data=data,_safe=_safe)
        return result

    @verbose(verbose_flag)
    def makealistsettablenew3(self,data,header,exclude=None,textarea=None,_safe=None):
        temp = """
        <div class="tablewrapper">
        <table>
            <thead>
                <tr>
                  <th>{{ header }}</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    {% if _safe == None %}
                        <td class="nobackgroundcolor"><pre class="breaklines">{{data|e}}</pre></td>
                    {% else %}
                        <td class="nobackgroundcolor"><pre class="breaklines">{{data|safe}}</pre></td>
                    {% endif %}
                </tr>
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.addtextarea()
        result = Template(temp).render(header=header,data=data,_safe=_safe)
        return result


    @verbose(verbose_flag)
    def makeworldimage(self,data,header,exclude=None,textarea=None):
        _data = []
        for _ in data:
            if _["Code"]:
                _data.append(_["Code"])
        temp = """
        <div class="tablewrapper">
        <table>
            <thead>
                <tr>
                    <th colspan="1">{{ header }}</th>
                </tr>
            </thead>
            <tbody>
                   <tr>
                        <td class="nobackgroundcolor"><canvas class="worldmap"></canvas></td>
                        <script>
                        var canvas = d3.select(".worldmap").attr("width", '960').attr("height", '500');
                        var context = canvas.node().getContext("2d");
                        var proj = d3.geo.equirectangular(),color = d3.scale.category20(),graticule = d3.geo.graticule();
                        var path = d3.geo.path().projection(proj).context(context);
                        context.strokeStyle = '#000';
                        context.beginPath();
                        path(graticule());
                        context.lineWidth = .5;
                        context.stroke();
                        context.strokeStyle = '#333';
                        context.beginPath();
                        path(graticule.outline());
                        context.lineWidth = 1.5;
                        context.stroke();
                        function colorcountry(d){if ({{ data|safe }}.includes(parseInt(d.id))){return "#585858";}else{return "#A9A9A9";}};
                        d3.json("https://unpkg.com/world-atlas@1/world/110m.json", function(error, world) {
                          var countries = topojson.feature(world, world.objects.countries).features
                              countries.forEach(function(d, i) {
                                  context.fillStyle = colorcountry(d)
                                  context.beginPath();
                                  path(d);
                                  context.fill();
                                  return 1;
                              });
                        });

                        </script>
                    </tr>
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.addtextarea()
        result = Template(temp).render(header=header,data=str(_data))
        return result

    @verbose(verbose_flag)
    def makexrefmapimage(self,data,header,exclude=None,textarea=None):
        temp = """
        <div class="tablewrapper">
        <table>
            <thead>
                <tr>
                    <th colspan="1">{{ header }}</th>
                </tr>
            </thead>
            <tbody>
                   <tr>
                        <td class="nobackgroundcolor"><svg class="xrefmap"></svg></td>
                        <script>
                        var width = 2000,
                            height = 2000,
                            radius = 10;
                           var svg = d3.select(".xrefmap").attr("width", width).attr("height", height);
                            var dataset = {{ data|safe }};
                            var force = d3.layout.force()
                                .nodes(dataset["nodes"])
                                .links(dataset["links"])
                                .linkDistance(100)
                                .theta(0.1)
                                .size([width,height])
                                .charge(-1000)
                                .start();
                            var links = svg.selectAll("line")
                              .data(dataset["links"])
                              .enter()
                              .append("line")
                              .attr('marker-end','url(#arrowhead)')
                              .style("stroke","#000")
                              .style("pointer-events", "none");
                            var nodes = svg.selectAll("circle")
                              .data(dataset["nodes"])
                              .enter().append("circle")
                              .attr("r", radius - .75)
                              .style("fill",function() {return "hsl(" + Math.random() * 360 + ",100%,50%)";})
                              .call(force.drag)
                            var nodelabels = svg.selectAll(".nodelabel") 
                               .data(dataset["nodes"])
                               .enter()
                               .append("text")
                               .text(function(d){return d["func"];});
                            var linkpaths = svg.selectAll(".linkpath")
                                .data(dataset["links"])
                                .enter()
                                .append('path')
                                .attr('fill-opacity',0)
                                .attr('id',function(d,i) {return 'linkpath'+i})
                                .style("pointer-events", "none");
                            var linklabels = svg.selectAll(".linklabel")
                                .data(dataset["links"])
                                .enter()
                                .append('text')
                                .style("pointer-events", "none")
                                .attr('font-size',10)
                                .attr('dy',0)
                                .attr('dx',50)
                                .attr('fill','#000');
                            linklabels.append('textPath')
                                .attr('xlink:href',function(d,i) {return '#linkpath'+i})
                                .style("pointer-events", "none");
                                //.text(function(d,i){return 'label '+i});
                              svg.append('defs').append('marker')
                                  .attr('id', 'arrowhead')
                                  .attr('viewBox', '0 -5 10 10')
                                  .attr('refX', 20)
                                  .attr('refY', 0)
                                  .attr('markerWidth', 8)
                                  .attr('markerHeight', 8)
                                  .attr('orient', 'auto')
                                .append('path')
                                  .attr('d', 'M0,-5L10,0L0,5')
                                  .attr('fill', '#000');

                            force.on("tick", function(){

                                links.attr({"x1": function(d){return d["source"].x;},
                                            "y1": function(d){return d["source"].y;},
                                            "x2": function(d){return d["target"].x;},
                                            "y2": function(d){return d["target"].y;}});

                                nodes.attr("cx", function(d) { return d.x = Math.max(radius, Math.min(width - radius, d.x)); })
                                .attr("cy", function(d) { return d.y = Math.max(radius, Math.min(height - radius, d.y)); });

                                nodelabels.attr("x", function(d) { return d.x; }) 
                                          .attr("y", function(d) { return d.y; });
                                linkpaths.attr('d', function (d) {return 'M ' + d["source"].x + ' ' + d["source"].y + ' L ' + d["target"].x + ' ' + d["target"].y;});       

                            });
                        </script>
                    </tr>
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.addtextarea()
        result = Template(temp).render(header="Xrefs",data=str(data))
        return result

    @verbose(verbose_flag)
    @progressbar(True,"Making file tables")
    def maketable(self,data,_path):
        table = ""
        for x in data:
            for key in data[x]:
                try:
                    if key.startswith("_"):
                        if x == "MITRE":
                            safe = True
                        else:
                            safe = None
                        if type(data[x][key]) is list:
                            if len(data[x][key[1:]]) > 0:
                                table += self.makealistsettablenew1(data[x][key[1:]],data[x][key],None,True,safe)
                        elif type(data[x][key]) is dict:
                            if len(data[x][key[1:]]) > 0:
                                table += self.makealistsettablenew2(data[x][key[1:]],["key","value"],None,True,safe)
                        elif type(data[x][key]) is str:
                            if len(data[x][key[1:]]) > 0:
                                table += self.makealistsettablenew3(data[x][key[1:]],key[1:],None,True,safe)
                        if key[1:] == "IPS" and len(data[x][key[1:]]) > 0 and x == "PCAP":
                            table +=self.makeworldimage(data[x][key[1:]],None,None,True)
                    elif key == "GRAPH" and len(data[x][key]) > 0 and x == "XREFS":
                        if data["XREFS"]["GRAPH"]["nodes"] and data["XREFS"]["GRAPH"]["links"]:
                            table +=self.makexrefmapimage(data[x][key],None,None,True)
                except:
                    pass

        table += self.makeimagetablebase64(self.qbi.createimage(_path,"16","100"),"Image",None,True)
        return table

    @verbose(verbose_flag)
    def rendertemplate(self,data,header,footer):
        footer = 'QBAnalyzer∞ generated this report at {} on {} - {}'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),platform(),self.d)
        table = self.maketable(data,data["Location"]["File"])
        table = "\n".join([line.rstrip() for line in table.splitlines() if line.strip()])
        with open(self.template) as file_:
            out = Template(file_.read()).render(title=data["Details"]["Properties"]["md5"],content=table,footer=footer)
        with open(data["Location"]["html"],"w") as file_:
            file_.write(out)
