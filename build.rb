#!/usr/bin/env ruby

require 'nokogiri'
require 'fileutils'

VER = "0.9.0"

FLAGS = {
	'R' => 'PIV_SUPPORT_RSA',
	'E' => 'PIV_SUPPORT_EC',
	'e' => 'PIV_SUPPORT_ECCP384',
	'P' => 'PIV_USE_EC_PRECOMPHASH',
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
build(VER, 'jc221', 'RESaD')
build(VER, 'jc221', 'RESAaD')
build(VER, 'jc221', 'RESLaD')
build(VER, 'jc221', 'RESLD')

build(VER, 'jc222', 'RESAaD')
build(VER, 'jc222', 'RESAxaD')
build(VER, 'jc222', 'RESxLD')

build(VER, 'jc304', 'EPSxLaD')
build(VER, 'jc304', 'RSxLaD')
build(VER, 'jc304', 'REePSAa')
build(VER, 'jc304', 'REePSAaD')
build(VER, 'jc304', 'REePSAxa')
build(VER, 'jc304', 'REePSAxaD')
