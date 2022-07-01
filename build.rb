#!/usr/bin/env ruby

require 'nokogiri'
require 'fileutils'

VER = "0.9.0"

FLAGS = {
	'R' => 'PIV_SUPPORT_RSA',
	'E' => 'PIV_SUPPORT_EC',
	'e' => 'PIV_SUPPORT_ECCP384',
	'S' => 'PIV_STRICT_CONTACTLESS',
	'A' => 'YKPIV_ATTESTATION',
	'x' => 'APPLET_EXTLEN',
	'L' => 'APPLET_LOW_TRANSIENT',
	'a' => 'PIV_SUPPORT_AES',
	'D' => 'PIV_SUPPORT_3DES'
}

$xmlbase = Nokogiri::XML(File.open('build.xml'))
FLAGS.each do |_,fl|
	a = $xmlbase.xpath("//property[@name='#{fl}']")
	a[0]['value'] = 'false'
end

def setup_config(jcver, flags)
	buildxml = $xmlbase.dup
	flags.split('').each do |flabbr|
		fl = FLAGS[flabbr]
		a = buildxml.xpath("//property[@name='#{fl}']")
		a[0]['value'] = 'true'
	end
	f = File.open('build.xml', 'w')
	f.write(buildxml.to_s)
	f.close()
	ENV['JC_HOME'] = ENV['JC_SDKS'] + "/#{jcver}_kit"
end

def build(ver, jcver, flags)
	setup_config(jcver, flags)
	`ant clean`
	`ant`
	FileUtils.mv('bin/PivApplet.cap', "dist/PivApplet-#{ver}-#{jcver}-#{flags}.cap")
end

`rm -fr dist`
`mkdir dist`
build(VER, 'jc221', 'RSaD')
build(VER, 'jc221', 'RSAaD')
build(VER, 'jc221', 'RSLaD')
build(VER, 'jc221', 'RSLD')

build(VER, 'jc222', 'RSAaD')
build(VER, 'jc222', 'RSAxaD')
build(VER, 'jc222', 'RAxaD')
build(VER, 'jc222', 'RSxLD')

build(VER, 'jc304', 'ESxLaD')
build(VER, 'jc304', 'RSxLaD')
build(VER, 'jc304', 'REeSAa')
build(VER, 'jc304', 'REeSAaD')
build(VER, 'jc304', 'REeSAxa')
build(VER, 'jc304', 'REeSAxaD')
build(VER, 'jc304', 'REeAxaD')
