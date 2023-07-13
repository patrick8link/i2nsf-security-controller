#! /bin/sh

NAME="$1"
shift

cat <<EOF
<html>
<head>
    <title>${NAME}</title>
</head>
<body>
    <h1>${NAME} Python module index</h1>
EOF

while [ $# -gt 0 ]; do
    MODULE="$1"
    shift
    echo "    <p><a href="${MODULE}.html">${MODULE}</a></p>"
done

echo "</body>"

exit 0
