#!/bin/sh

generate_index_html() {
  testlogs_dir=$1

  outfile=$testlogs_dir/index.html
  echo "<html><body>i<p>Last update: $(date)</p>" > $outfile
  echo "<p><ul>" >> $outfile
  for f in `ls $testlogs_dir | egrep '(txt)'`; do
    report=$(grep 'Tests run: [0-9]\{1,\},  Failures: [0-9]\{1,\}' $testlogs_dir/$f)
    test_name=$f
    if [[ $f = *"BouncyCastle"* ]]; then
      test_name="SpongyCastle/$f"
    fi
    echo "<li><a href=\"$f\">$test_name</a>: $report</li>" >> $outfile;
  done;
  echo "</ul></p></body></html>" >> $outfile;
}

generate_index_html .
