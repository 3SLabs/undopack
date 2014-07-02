operations = [
    proc {
      ['write',rand(0x7fffffff), [1,2,3,4,5,6,7,8].sample()]
    },
    proc {
      ['image_load', rand(0x7fffffff), 0x1000 + rand(0x1000)]
    }
]

(ARGV[0] || 100000).to_i.times do
  puts operations.sample().call().join(":")
end


