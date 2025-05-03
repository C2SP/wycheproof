# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import math

# Instead of redrawing the same graphics in multiple styles we
# construct them with some code. The main target is SVG. 

# TODO: Might use markers:
'''
  <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <!-- arrowhead marker definition -->
    <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5"
        markerWidth="6" markerHeight="6"
        orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" />
    </marker>

    <!-- simple dot marker definition -->
    <marker id="dot" viewBox="0 0 10 10" refX="5" refY="5"
        markerWidth="5" markerHeight="5">
      <circle cx="5" cy="5" r="5" fill="red" />
    </marker>
  </defs>

  <!-- Coordinate axes with a arrowhead in both direction -->
  <polyline points="10,10 10,90 90,90" fill="none" stroke="black"
   marker-start="url(#arrow)" marker-end="url(#arrow)"  />

  <!-- Data line with polymarkers -->
  <polyline points="15,80 29,50 43,60 57,30 71,40 85,15" fill="none" stroke="grey"
   marker-start="url(#dot)" marker-mid="url(#dot)"  marker-end="url(#dot)" />
</svg>
'''
# TODO: might use path:

# Types
coordinate = float
length = float
color = str

class SvgCanvas:
  def __init__(self, sizex=0, sizey=0):
    self.reset(sizex, sizey)

  def reset(self, sizex, sizey):
    self.sizex = sizex
    self.sizey = sizey
    self.lines = []

  def getText(self):
    '''Returns an SVG representation of the graphic'''
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>\n' + 
        '<svg viewBox="0 0 %s %s"\n' % (self.sizex, self.sizey) +
        'xmlns="http://www.w3.org/2000/svg" version="1.1">\n' +
        '<style>\n' +
        ' .label { font: italic 14px sans-serif; }\n' +
        '</style>' + 
        '\n'.join(self.lines) +
        '\n</svg>')

  def rect(self,
           x:coordinate, 
           y:coordinate,
           width:length,
           height:length,
           fill:color,
           stroke:color,
           stroke_width:length):
    self.lines.append(
        '<rect x="%s" y="%s" width="%s" height="%s" fill="%s" stroke="%s"'
        ' stroke-width="%s"/>'
        % (x, y, width, height, fill, stroke, stroke_width))

  def polyline(self,
               points,
               fill:color="none", 
               stroke:color="none",
               stroke_width:length=0):
    pts = ' '.join("%s,%s" % p for p in points)
    self.lines.append('<polyline fill="%s" stroke="%s" stroke_width="%s"'
                      ' points="%s"/>' % (fill, stroke, stroke_width, pts))
            
  def arrow(self,
            points,
            fill:color="none", 
            stroke:color="none",
            stroke_width:length=0,
            arrow_height:length=0):
    if len(points) < 2: return
    x,y = points[-1]
    u,v = points[-2]
    lx, ly = u-x, v-y
    l = math.sqrt(lx*lx + ly*ly)
    dx = lx * arrow_height / l
    dy = ly * arrow_height / l
    r = x + dx
    s = y + dy
    tpoints = list(points[:-1]) + [(r,s)]
    pts = ' '.join("%s,%s" % p for p in tpoints)
    self.lines.append('<polyline fill="%s" stroke="%s" stroke_width="%s"'
                      ' points="%s"/>' % (fill, stroke, stroke_width, pts))
    arrow_points = [(x,y), (r - dy/2, s + dx/2), (r + dy/2, s - dx/2)]
    pts = ' '.join("%s,%s" % p for p in arrow_points)
    self.lines.append('<polygon fill="%s" points="%s"/>' % (stroke, pts))

  def label(self, x, y, txt):
    self.lines.append('<text text-anchor="middle" class="label"' +
                      ' x="%s" y="%s">%s</text>' % (x, y, txt))

def kwp(canvas,
        blocks,
        rounds:int,
        boxwidth:length,
        boxheight:length,
        boxfill:color,
        spacewidth:length,
        spaceheight:length,
        borderwidth:length,
        borderheight:length,
        stroke_width:length,
        stroke="black"):

  def addline(*pts):
    canvas.polyline(pts, stroke=stroke, stroke_width=stroke_width)

  def addarrow(*pts):
    canvas.arrow(pts, stroke=stroke, stroke_width=stroke_width,
                 arrow_height=1.8*stroke_width)

  def addlabel(x, y, txt):
    canvas.label(x, y, txt)

  def right(i):
    '''the x-coodinate of the right input of block i'''
    return borderwidth + i * (boxwidth + spacewidth) + 3 * boxwidth / 4

  def left(i):
    '''the x-coodinate of the left input of block i'''
    return borderwidth + i * (boxwidth + spacewidth) + boxwidth / 4

  def upper(i):
    return borderheight + i * (boxheight + spaceheight)

  def lower(i):
    return upper(i) + boxheight

  width = blocks * boxwidth + 2 * borderwidth + (blocks - 1) * spacewidth
  height = rounds * boxheight + 2 * borderheight + (rounds - 1) * spaceheight
  canvas.reset(width, height)
  canvas.rect(0, 0, width, height, fill="white", stroke="none", stroke_width=0)
  # IV
  addarrow((left(0), lower(-1)), (left(0), upper(0)))

  for i in range(blocks):
    addarrow((right(i), lower(-1)), (right(i), upper(0)))

  for j in range(rounds):
    for i in range(blocks):
      x = borderwidth + i * (boxwidth + spacewidth)
      y = borderheight + j * (boxheight + spaceheight)
      canvas.rect(x, y, boxwidth, boxheight, fill=boxfill, stroke=stroke, 
                  stroke_width=stroke_width/2)
      r = right(i)
      l = left(i+1)
      if i < blocks - 1:
        m = (r + l) / 2
        addarrow((left(i), y + boxheight),
                (left(i), y + boxheight + spaceheight / 4),
                (m, y + boxheight + spaceheight / 4),
                (m, y - spaceheight / 4),
                (l, y - spaceheight / 4),
                (l, y))
      addarrow((r, y + boxheight),
               (r, y + boxheight + spaceheight))
    x0 = left(0)
    y = borderheight + (j + 1) * boxheight + j * spaceheight
    xn = left(blocks - 1)
    addarrow((xn, y), (xn, y + spaceheight / 2), (x0, y + spaceheight / 2),
            (x0, y + spaceheight))
  yupper = lower(-1) - 5 
  addlabel(left(0), yupper, 'IV')
  for i in range(blocks):
    addlabel(right(i), yupper, 'm[%s]' % i)
  ylower = upper(rounds) + 12
  addlabel(left(0), ylower, 'c[0]')
  for i in range(blocks):
    addlabel(right(i), ylower, 'c[%s]' % (i+1))

if __name__ == "__main__":  
  C = SvgCanvas()
  kwp(C, 
      blocks=6, 
      rounds=6,
      boxwidth=45, 
      boxheight=20,
      boxfill="lightblue",
      spacewidth=20, 
      spaceheight=20, 
      borderwidth=40,
      borderheight=60, 
      stroke_width=2)
  print(C.getText())



