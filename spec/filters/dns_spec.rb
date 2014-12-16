# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/dns"
require "resolv"

describe LogStash::Filters::DNS do
  before(:each) do
    allow_any_instance_of(Resolv).to receive(:getaddress).with("carrera.databits.net").and_return("199.192.228.250")
    allow_any_instance_of(Resolv).to receive(:getaddress).with("does.not.exist").and_raise(Resolv::ResolvError)
    allow_any_instance_of(Resolv).to receive(:getaddress).with("nonexistanthostname###.net").and_raise(Resolv::ResolvError)
    allow_any_instance_of(Resolv).to receive(:getname).with("199.192.228.250").and_return("carrera.databits.net")
    allow_any_instance_of(Resolv).to receive(:getname).with("127.0.0.1").and_return("localhost")
    allow_any_instance_of(Resolv).to receive(:getname).with("128.0.0.1").and_raise(Resolv::ResolvError)
    allow_any_instance_of(Resolv).to receive(:getname).with("199.192.228.250").and_return("carrera.databits.net")
  end

    describe "dns reverse lookup, no target" do
      config <<-CONFIG
      filter {
        dns {
          source => "host"
        }
      }
      CONFIG

      sample("host" => "199.192.228.250") do
        insist { subject["host"] } == "199.192.228.250"
        insist { subject["dns"] } == "carrera.databits.net"
      end
    end

    describe "dns lookup, with target" do
      config <<-CONFIG
      filter {
        dns {
          source => "foo"
          target => "bar"
        }
      }
      CONFIG

      sample("foo" => "199.192.228.250") do
        insist { subject["foo"] } == "199.192.228.250"
        insist { subject["bar"] } == "carrera.databits.net"
      end
    end

    describe "dns lookup, NXDOMAIN, no target" do
      config <<-CONFIG
      filter {
        dns {
          source => "foo"
        }
      }
      CONFIG

      sample("foo" => "doesnotexist.invalid.topleveldomain") do
        insist { subject["foo"] } == "doesnotexist.invalid.topleveldomain"
        insist { subject["dns"] } == nil
      end
    end

    describe "dns lookup, NXDOMAIN, with target" do
      config <<-CONFIG
      filter {
        dns {
          source => "foo"
          target => "bar"
        }
      }
      CONFIG

      sample("foo" => "doesnotexist.invalid.topleveldomain") do
        insist { subject["foo"] } == "doesnotexist.invalid.topleveldomain"
        insist { subject["bar"] } == nil
      end
    end
  end
end
