# generate keys
python mhcrack.py --key_pub_file MY_PUBLIC_KEY.json --key_priv_file MY_PRIVATE_KEY.json --regime generate --complexity 10 --bits 10

# encode text
python mhcrack.py --key_pub_file MY_PUBLIC_KEY.json  --regime cypher --text your_text_here --cypher_file my_cypher_file.txt

# decode text
python mhcrack.py --key_pub_file MY_PUBLIC_KEY.json --regime hack --cypher_file my_cypher_file.txt

# interactive regime
python mhcrack.py --regime interactive
