__G__ = "(G)bd249ce4"

from ..logger.logger import verbose, verbose_flag, verbose_timeout
from jinja2 import Template
from platform import platform
from datetime import datetime
from sys import modules
from os import mkdir, path

class HtmlMaker:
    @verbose(True,verbose_flag,verbose_timeout,"Starting HtmlMaker")
    def __init__(self,qbimage,qbicons):
        '''
        initialize class
        '''
        self.templates = path.abspath(path.join(path.dirname( __file__ ),'templates'))
        if not self.templates.endswith(path.sep): self.templates = self.templates+path.sep
        if not path.isdir(self.templates): mkdir(self.templates)
        self.template = self.templates + "template.html"
        self.qbimage = qbimage()
        self.qbicons = qbicons()
        self.get_moudles()

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_moudles(self):
        '''
        get all imported modules 
        '''
        x = [x.split(".")[0] for x in modules.keys() if not x.startswith("_")]
        self.d = '(QBAnalyzer∞ proudly uses/depends on Docker, Python3, Bootstrap, Javascript, jquery, D3.js, JSON, Html, Sqlite3, Wikipedia, Linux\\MacOS\\Windows\\Android documentation, software77, MITRE ATT&CK™, sc0ty, hexacorn, radare2, dmg2img, snort, font-awesome, flag-icon-css, {} and tons of researches ..) If i missed a reference/dependency, please let me know!'.format(', '.join(list(set(x))))

    @verbose(True,verbose_flag,verbose_timeout,None)
    def add_text_area(self) -> str:
        '''
        textarea tag
        '''
        return """<div class=textareawrapper><textarea rows="1"></textarea></div>"""

    @verbose(True,verbose_flag,verbose_timeout,None)
    def empty_text_area(self) -> str:
        '''
        textarea tag
        '''
        return """<div class=empty></div>"""


    @verbose(True,verbose_flag,verbose_timeout,"Making yara table")
    def make_yara_table(self,data) -> str:
        '''
        add start generating yara html table 
        '''
        table = ""
        if len(data) > 0:
            table += self.makelisttableforyara(data,["Offset","Rule","String","Parsed","Condition"],None,True)
        return table

    @verbose(True,verbose_flag,verbose_timeout,None)
    def make_image_table_base64(self,data,header,exclude=None,textarea=None,_safe=None) -> str:
        '''
        render similarity image inside html table
        '''
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
                        <td><img class="fullsize" src="{{ data }}" /></td>
                    </tr>
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.add_text_area()
        else: temp += self.empty_text_area()
        result = Template(temp).render(header=header,data=data)
        return result

    @verbose(True,verbose_flag,verbose_timeout,None)
    def make_icons_table_base64(self,data,header,exclude=None,textarea=None,_safe=None) -> str:
        '''
        render similarity image inside html table
        '''
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
                        <td class="icons">{% for item in data %}<img src="{{ item[0] }}" height="{{ item[1][0] }}" width="{{ item[1][1] }}"/>{% endfor %}</td>
                    </tr>
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.add_text_area()
        else: temp += self.empty_text_area()
        result = Template(temp).render(header=header,data=data,size=len(data))
        return result

    @verbose(True,verbose_flag,verbose_timeout,None)
    def make_list_set_table_new1(self,data,headers,exclude=None,textarea=None,_safe=None) -> str:
        '''
        render list into html table
        '''
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
        if textarea: temp += self.add_text_area()
        else: temp += self.empty_text_area()
        result = Template(temp).render(headers=headers,data=data,_safe=_safe)
        return result

    @verbose(True,verbose_flag,verbose_timeout,None)
    def make_list_set_table_new2(self,data,headers,exclude=None,textarea=None,_safe=None) -> str:
        '''
        render dict into html table
        '''
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
        if textarea: temp += self.add_text_area()
        else: temp += self.empty_text_area()
        result = Template(temp).render(headers=headers,data=data,_safe=_safe)
        return result

    @verbose(True,verbose_flag,verbose_timeout,None)
    def make_list_set_table_new3(self,data,header,exclude=None,textarea=None,_safe=None) -> str:
        '''
        render text into html table
        '''
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
        if textarea: temp += self.add_text_area()
        else: temp += self.empty_text_area()
        result = Template(temp).render(header=header,data=data,_safe=_safe)
        return result

    @verbose(True,verbose_flag,verbose_timeout,None)
    def make_list_set_table_new4(self,data,headers,exclude=None,textarea=None,_safe=None) -> str:
        '''
        render dict into html table
        '''
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
                    {% for key, value in item.items() %}
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
                {% endfor %}
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.add_text_area()
        else: temp += self.empty_text_area()
        result = Template(temp).render(headers=headers,data=data,_safe=_safe)
        return result

    @verbose(True,verbose_flag,verbose_timeout,None)
    def make_flags(self,data,header,exclude=None,textarea=None,_safe=None) -> str:
        '''
        render similarity image inside html table
        '''
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
                        <td class="flags">{% for item in data %}<span class="flag-icon flag-icon-{{ item }}"></span>{% endfor %}</td>
                    </tr>
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.add_text_area()
        else: temp += self.empty_text_area()
        result = Template(temp).render(header=header,data=data)
        return result

    @verbose(True,verbose_flag,verbose_timeout,None)
    def make_world_image(self,data,header,name,exclude=None,textarea=None,_safe=None) -> str:
        '''
        render world image into html table
        '''
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
                        <td id="{{name}}" class="nobackgroundcolor"><canvas class="{{name}}"></canvas></td>
                        <script>
                        //contact me for license
                        (function() {
                        var canvas = d3.select(".{{name}}").attr("width", '960').attr("height", '500');
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
                        })();
                        </script>
                    </tr>
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.add_text_area()
        else: temp += self.empty_text_area()
        result = Template(temp).render(header=header,data=str(data),name=name)
        return result

    @verbose(True,verbose_flag,verbose_timeout,None)
    def make_ref_map_image(self,data,header,name,exclude=None,textarea=None,_safe=None) -> str:
        '''
        render xref image into html table
        '''
        temp = """
        <div class="tablewrapper">
        <table>
            <thead>
                <tr>
                    <th colspan="1">{{header}}</th>
                </tr>
            </thead>
            <tbody>
                   <tr>
                        <td id="{{name}}" class="nobackgroundcolor"><svg class="{{name}}"></svg></td>
                        <script>
                        //contact me for license
                        (function() {
                        var width = 1000,
                            height = 1000,
                            radius = 10;
                        var svg = d3.select(".{{name}}").attr("width", width).attr("height", height);
                        var dataset = {{data | safe}};
                        var force = d3.layout.force()
                            .nodes(dataset["nodes"])
                            .links(dataset["links"])
                            .linkDistance(100)
                            .theta(0.1)
                            .size([width, height])
                            .charge(-1000)
                            .start();
                        var links = svg.selectAll("line")
                            .data(dataset["links"])
                            .enter()
                            .append("line")
                            .attr('marker-end', 'url(#arrowhead)')
                            .style("stroke", "#000")
                            .style("pointer-events", "none");
                        var nodes = svg.selectAll("circle")
                            .data(dataset["nodes"])
                            .enter().append("circle")
                            .attr("r", radius - .75)
                            .style("fill", function() {
                                return "hsl(" + Math.random() * 360 + ",100%,50%)";
                            })
                            .call(force.drag)
                        var nodelabels = svg.selectAll(".nodelabel")
                            .data(dataset["nodes"])
                            .enter()
                            .append("text")
                            .text(function(d) {
                                return d["func"];
                            });
                        var linkpaths = svg.selectAll(".linkpath")
                            .data(dataset["links"])
                            .enter()
                            .append('path')
                            .attr('fill-opacity', 0)
                            .attr('id', function(d, i) {
                                return 'linkpath' + i
                            })
                            .style("pointer-events", "none");
                        var linklabels = svg.selectAll(".linklabel")
                            .data(dataset["links"])
                            .enter()
                            .append('text')
                            .style("pointer-events", "none")
                            .attr('font-size', 10)
                            .attr('dy', 0)
                            .attr('dx', 50)
                            .attr('fill', '#000');
                        linklabels.append('textPath')
                            .attr('xlink:href', function(d, i) {
                                return '#linkpath' + i
                            })
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

                        resize();
                        d3.select(window).on("resize.{{name}}", resize);

                        force.on("tick", function() {

                            links.attr({
                                "x1": function(d) {
                                    return d["source"].x;
                                },
                                "y1": function(d) {
                                    return d["source"].y;
                                },
                                "x2": function(d) {
                                    return d["target"].x;
                                },
                                "y2": function(d) {
                                    return d["target"].y;
                                }
                            });

                            nodes.attr("cx", function(d) {
                                    return d.x = Math.max(radius, Math.min(width - radius, d.x));
                                })
                                .attr("cy", function(d) {
                                    return d.y = Math.max(radius, Math.min(height - radius, d.y));
                                });

                            nodelabels.attr("x", function(d) {
                                    return d.x;
                                })
                                .attr("y", function(d) {
                                    return d.y;
                                });
                            linkpaths.attr('d', function(d) {
                                return 'M ' + d["source"].x + ' ' + d["source"].y + ' L ' + d["target"].x + ' ' + d["target"].y;
                            });

                        });

                        function resize() {
                            width = document.getElementById("{{name}}").clientWidth - 20; //for padding
                            height = document.getElementById("{{name}}").clientHeight;
                            svg.attr("width", width).attr("height", height);
                            force.size([width, height]).resume();
                        }
                        })();
                        </script>
                    </tr>
            </tbody>
        </table>
        </div>"""
        if textarea: temp += self.add_text_area()
        else: temp += self.empty_text_area()
        result = Template(temp).render(header="Xrefs",data=str(data),name=name)
        return result

    @verbose(True,verbose_flag,verbose_timeout,"Making file tables")
    def make_table(self,data,_path,parsed) -> str:
        '''
        making tables of dict data
        '''
        table = ""
        for x in data:
            for key in data[x]:
                try:
                    if key.startswith("_____"):
                        if len(data[x][key[5:]]) > 0:
                            table += self.make_list_set_table_new3(data[x][key[5:]],key[5:],None,False,None)
                    elif key.startswith("____"):
                        if len(data[x][key[4:]]) > 0:
                            table += self.make_list_set_table_new4(data[x][key[4:]],["key","value"],None,False,None)
                    elif key.startswith("___"):
                        if len(data[x][key[3:]]) > 0:
                            for item in data[x][key[3:]]:
                                table += self.make_list_set_table_new2(item,["key","value"],None,False,None)
                    elif key.startswith("__"):
                        if len(data[x][key[2:]]) > 0:
                            for item in data[x][key[2:]]:
                                table += self.make_list_set_table_new2(data[x][key[2:]][item],["key","value"],None,False,None)
                    elif key.startswith("_"):
                        if x == "MITRE":
                            safe = True
                        else:
                            safe = None
                        if type(data[x][key]) is list:
                            if len(data[x][key[1:]]) > 0:
                                table += self.make_list_set_table_new1(data[x][key[1:]],data[x][key],None,False,safe)
                        elif type(data[x][key]) is dict:
                            if len(data[x][key[1:]]) > 0:
                                table += self.make_list_set_table_new2(data[x][key[1:]],["key","value"],None,False,safe)
                        elif type(data[x][key]) is str:
                            if len(data[x][key[1:]]) > 0:
                                table += self.make_list_set_table_new3(data[x][key[1:]],key[1:],None,False,safe)
                    elif key == "GRAPH" or key == "Flags":
                        pass
                except:
                    pass

        if parsed.xref or parsed.full:
            for key in ("XREFS","REFS"):
                if key in data and "GRAPH" in data[key]:
                    if data[key]["GRAPH"]["nodes"] and data[key]["GRAPH"]["links"]:
                        table +=self.make_ref_map_image(data[key]["GRAPH"],key,key+"d3map",None,False,None)

        if parsed.flags or parsed.full:
            if "Flags" in data:
                if len(data["Flags"]["Flags"]) > 0:
                    table +=self.make_flags(data["Flags"]["Flags"],"Flags",None,False,None)

        if parsed.worldmap or parsed.full:
            if "Codes" in data:
                if len(data["Codes"]["Codes"]) > 0:
                    table +=self.make_world_image(data["Codes"]["Codes"],"Worldmap","Worldmap",None,False,None)

        if parsed.icons or parsed.full:
            if "ICONS" in data:
                if len(data["ICONS"]["ICONS"]) > 0:
                    out = self.qbicons.create(data["ICONS"]["ICONS"])
                    table += self.make_icons_table_base64(out,"ICONS",None,False,None)                    

        if parsed.image or parsed.full:
            out,c = self.qbimage.create(data["FilesDumps"][_path])
            table += self.make_image_table_base64(out,c,None,False,None)
        return table

    @verbose(True,verbose_flag,verbose_timeout,None)
    def render_template(self,data,header,footer,parsed,dump=False):
        '''
        start making tables and save them into a html file
        '''
        footer = 'QBAnalyzer∞ generated this report at {} on {} - {}'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),platform(),self.d)
        table = self.make_table(data,data["Location"]["File"],parsed)
        table = "\n".join([line.rstrip() for line in table.splitlines() if line.strip()])
        if dump:
            with open(self.template) as file:
                Template(file.read()).stream(title=data["Details"]["Properties"]["md5"],content=table,footer=footer).dump(data["Location"]["html"])
                if path.exists(data["Location"]["html"]):
                    return True
        else:
            with open(self.template) as file:
                rendered = Template(file.read()).render(title=data["Details"]["Properties"]["md5"],content=table,footer=footer)
                return rendered
        return None