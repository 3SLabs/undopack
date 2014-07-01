operations = [
    proc {
      ['write', rand(0xffffffff), [1,2,3,4,5,6,7,8].sample()]
    },
    proc {
      ['image_load', rand(0xffffffff), 0x1000 + rand(0x100000)]
    }
]

(ARGV[0] || 100000).to_i.times do
  puts operations.sample().call().join(":")
end


