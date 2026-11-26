-- pandoc filter for "make man-md": the man pages as GitHub Markdown.

-- .RS is an indent, not a quotation.
function BlockQuote(el)
  return el.content
end

-- An example is fenced, so it keeps its indentation and is not read as a
-- quotation or a list.
function CodeBlock(el)
  if #el.classes == 0 then
    el.classes = { "text" }
  end
  return el
end

-- Bold and italic that touch (.BI, .BR) are written as HTML: "**a***b*" is
-- not read back as bold "a" and italic "b".
local function styled(el)
  return el.t == "Strong" or el.t == "Emph"
end

local function html(el)
  local tag = el.t == "Strong" and "b" or "i"
  local out = pandoc.List({ pandoc.RawInline("html", "<" .. tag .. ">") })
  out:extend(el.content)
  out:insert(pandoc.RawInline("html", "</" .. tag .. ">"))
  return out
end

local function space(el)
  return el and (el.t == "Space" or el.t == "SoftBreak")
end

function Inlines(inlines)
  -- A space at the edge of a styled run (.BI --host " NAME") goes outside it.
  local spaced = pandoc.List()
  for _, el in ipairs(inlines) do
    if styled(el) and space(el.content[1]) then
      spaced:insert(el.content:remove(1))
    end
    local tail = nil
    if styled(el) and space(el.content[#el.content]) then
      tail = el.content:remove()
    end
    spaced:insert(el)
    if tail then
      spaced:insert(tail)
    end
  end
  inlines = spaced
  local out = pandoc.List()
  for i, el in ipairs(inlines) do
    local prev, next = inlines[i - 1], inlines[i + 1]
    if styled(el) and ((prev and styled(prev)) or (next and styled(next))) then
      out:extend(html(el))
    else
      out:insert(el)
    end
  end
  return out
end
