#!/usr/bin/env ruby

require 'nokogiri'
require 'fileutils'

VER = "0.8.1"

FLAGS = {
	'R' => 'PIV_SUPPORT_RSA',
	'E' => 'PIV_SUPPORT_EC',
	'e' => 'PIV_SUPPORT_ECCP384',
	'P' => 'PIV_USE_EC_PRECOMPHASH',
	'S' => 'PIV_STRICT_CONTACTLESS',
	'A' => 'YKPIV_ATTESTATION',
	'x' => 'APPLET_EXTLEN',
	'L' => 'APPLET_LOW_TRANSIENT'
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
build(VER, 'jc221', 'RES')
build(VER, 'jc221', 'RESA')
build(VER, 'jc221', 'RESL')

build(VER, 'jc222', 'RESA')
build(VER, 'jc222', 'RESAx')
build(VER, 'jc222', 'RESxL')

build(VER, 'jc304', 'EPSxL')
build(VER, 'jc304', 'RSxL')
build(VER, 'jc304', 'REePSA')
build(VER, 'jc304', 'REePSAx')
