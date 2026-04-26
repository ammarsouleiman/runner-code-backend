from pathlib import Path  
  
p = Path(r"c:\Users\HP\OneDrive\Desktop\Runner Code New Version\AI website\Runner Code AI Platform\server\server.js")  
text = p.read_text(encoding="utf-8")  
lines = text.splitlines(keepends=True)  
  
start_marker = "// ── GET /api/conversations ──"  
occurrences = [i for i, l in enumerate(lines) if start_marker in l]  
print("Comment occurrences (1-indexed):", [i+1 for i in occurrences])  
  
real_idx = next(i for i, l in enumerate(lines) if l.startswith("app.get('/api/conversations'"))  
print("Real app.get('/api/conversations') at line:", real_idx + 1)  
  
# Sanity: occurrences[1] should be real_idx - 1  
assert occurrences[1] == real_idx - 1, f"mismatch: occurrences={occurrences}, real_idx={real_idx}"  
  
# Delete lines from occurrences[0] (inclusive) to occurrences[1] (exclusive)  
del_start, del_end = occurrences[0], occurrences[1]  
print(f"Deleting lines {del_start+1} .. {del_end} ({del_end - del_start} lines total)")  
print("First deleted line:", repr(lines[del_start])[:100])  
print("Last deleted line:", repr(lines[del_end-1])[:100])  
print("Kept line after delete:", repr(lines[del_end])[:100])  
  
new_lines = lines[:del_start] + lines[del_end:]  
p.write_text("".join(new_lines), encoding="utf-8")  
print("DONE. New total lines:", len(new_lines))  
  
# Verify: count remaining GET /api/conversations comments  
text2 = p.read_text(encoding="utf-8")  
print("Remaining '/api/conversations' comment occurrences:", text2.count(start_marker))  
print("Remaining 'POST /api/contact' comment occurrences:", text2.count("// ── POST /api/contact"))  
print("Remaining 'DELETE /admin/users/:id' comment occurrences:", text2.count("// ── DELETE /admin/users/:id"))  
