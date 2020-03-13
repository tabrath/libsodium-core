using NUnit.Framework;
using Sodium;
using System;
using System.Collections.Generic;

namespace Tests
{
  [TestFixture]
  public class PasswordHashTest
  {
    /// <summary>
    ///   Just a helper class.
    /// </summary>
    private class HashTestObject
    {
      public string Password { get; set; }
      public string Salt { get; set; }
      public long OpsLimit { get; set; }
      public int MemLimit { get; set; }
      public long OutputLength { get; set; }
    }

    /// <summary>Verify that the length of the returned salt is correct.</summary>
    [Test]
    public void ArgonGenerateSaltTest()
    {
      Assert.AreEqual(16, PasswordHash.ArgonGenerateSalt().Length);
    }

    /// <summary>
    ///   Derives a 16 byte long secret key from a password and a salt.
    /// </summary>
    [Test]
    public void ArgonHashBinary16ByteTest()
    {
      const string PASSWORD =
        "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e00cc2890277f0fd3c622115772f7048adaebed86e";
      const string SALT = "44071f6d181561670bda728d43fb79b4";
      const long OUTPUT_LENGTH = 16;
      var hash1 = PasswordHash.ArgonHashBinary(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT),
        PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash2 = PasswordHash.ArgonHashBinary(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT),
        PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash3 = PasswordHash.ArgonHashBinary(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT),
        PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH, PasswordHash.ArgonAlgorithm.Argon_2ID13);
      var hash4 = PasswordHash.ArgonHashBinary(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT),
        PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH, PasswordHash.ArgonAlgorithm.Argon_2ID13);

      Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
      Assert.AreEqual(hash1, hash2);

      Assert.AreEqual(OUTPUT_LENGTH, hash3.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash4.Length);
      Assert.AreEqual(hash3, hash4);
    }

    /// <summary>
    ///   Derives a 16 byte long secret key from a password and a salt.
    /// </summary>
    [Test]
    public void ArgonHashBinary16Test()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      const string SALT = "qa~t](84z<1t<1oz";
      const long OUTPUT_LENGTH = 16;
      var hash1 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash2 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash3 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH,
        PasswordHash.ArgonAlgorithm.Argon_2ID13);
      var hash4 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH,
        PasswordHash.ArgonAlgorithm.Argon_2ID13);

      Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
      Assert.AreEqual(hash1, hash2);

      Assert.AreEqual(OUTPUT_LENGTH, hash3.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash4.Length);
      Assert.AreEqual(hash3, hash4);
    }

    /// <summary>
    ///   Derives a 32 byte long secret key from a password and a salt.
    /// </summary>
    [Test]
    public void ArgonHashBinary32Test()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      const string SALT = "qa~t](84z<1t<1oz";
      const long OUTPUT_LENGTH = 32;
      var hash1 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash2 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash3 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH,
        PasswordHash.ArgonAlgorithm.Argon_2ID13);
      var hash4 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH,
        PasswordHash.ArgonAlgorithm.Argon_2ID13);

      Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
      Assert.AreEqual(hash1, hash2);

      Assert.AreEqual(OUTPUT_LENGTH, hash3.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash4.Length);
      Assert.AreEqual(hash3, hash4);
    }

    /// <summary>
    ///   Derives a 128 byte long secret key from a password and a salt.
    /// </summary>
    [Test]
    public void ArgonHashBinary128Test()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      const string SALT = "qa~t](84z<1t<1oz";
      const long OUTPUT_LENGTH = 128;
      var hash1 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash2 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash3 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH,
        PasswordHash.ArgonAlgorithm.Argon_2ID13);
      var hash4 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH,
        PasswordHash.ArgonAlgorithm.Argon_2ID13);

      Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
      Assert.AreEqual(hash1, hash2);

      Assert.AreEqual(OUTPUT_LENGTH, hash3.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash4.Length);
      Assert.AreEqual(hash3, hash4);
    }

    /// <summary>
    ///   Derives a 512 byte long secret key from a password and a salt.
    /// </summary>
    [Test]
    public void ArgonHashBinary512Test()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      const string SALT = "qa~t](84z<1t<1oz";
      const long OUTPUT_LENGTH = 512;
      var hash1 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash2 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH);
      var hash3 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH,
        PasswordHash.ArgonAlgorithm.Argon_2ID13);
      var hash4 = PasswordHash.ArgonHashBinary(PASSWORD, SALT, PasswordHash.StrengthArgon.Interactive, OUTPUT_LENGTH,
        PasswordHash.ArgonAlgorithm.Argon_2ID13);

      Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
      Assert.AreEqual(hash1, hash2);

      Assert.AreEqual(OUTPUT_LENGTH, hash3.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash4.Length);
      Assert.AreEqual(hash3, hash4);
    }

    [Test]
    public void ArgonHashStringTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      //See: https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html
      // (MEM_LIMIT: It is recommended to allow the function to use at least 32 megabytes.)
      const long OPS_LIMIT = 4;
      const int MEM_LIMIT = 33554432;

      var hash = PasswordHash.ArgonHashString(PASSWORD, OPS_LIMIT, MEM_LIMIT);

      Assert.IsTrue(PasswordHash.ArgonHashStringVerify(hash, PASSWORD));
    }

    [Test]
    public void ArgonHashStringInteractiveTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      var hash = PasswordHash.ArgonHashString(PASSWORD);

      Assert.IsTrue(PasswordHash.ArgonHashStringVerify(hash, PASSWORD));
    }

    [Test]
    public void ArgonHashStringModerateTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      var hash = PasswordHash.ArgonHashString(PASSWORD, PasswordHash.StrengthArgon.Moderate);

      Assert.IsTrue(PasswordHash.ArgonHashStringVerify(hash, PASSWORD));
    }

    [Test]
    public void ArgonHashStringSensitiveTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";

      try
      {
        //Could cause OutOfMemoryException
        var hash = PasswordHash.ArgonHashString(PASSWORD, PasswordHash.StrengthArgon.Sensitive);

        Assert.IsTrue(PasswordHash.ArgonHashStringVerify(hash, PASSWORD));
      }
      catch (OutOfMemoryException e)
      {
        Assert.Inconclusive(e.ToString());
      }
    }

    /// <summary>
    ///   Derives some secret keys from some test data.
    /// </summary>
    [Test]
    public void HashArgonLongTest()
    {
      try
      {
        //Could cause OutOfMemoryException
        //Some of the values are from: https://github.com/jedisct1/libsodium/blob/master/test/default/pwhash_scrypt.c
        var testObjects = new List<HashTestObject>
        {
          new HashTestObject
          {
            Password =
              "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae065577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08da232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f58d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
            Salt = "5541fbc995d5c197ba290346d2c559de",
            OpsLimit = 5,
            MemLimit = 7256678,
            OutputLength = 155
          },
          new HashTestObject
          {
            Password =
              "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e00cc2890277f0fd3c622115772f7048adaebed86e",
            Salt = "f1192dd5dc2368b9cd421338b2243345",
            OpsLimit = 4,
            MemLimit = 7849083,
            OutputLength = 250
          },
          new HashTestObject
          {
            Password =
              "92263cbf6ac376499f68a4289d3bb59e5a22335eba63a32e6410249155b956b6a3b48d4a44906b18b897127300b375b8f834f1ceffc70880a885f47c33876717e392be57f7da3ae58da4fd1f43daa7e44bb82d3717af4319349c24cd31e46d295856b0441b6b289992a11ced1cc3bf3011604590244a3eb737ff221129215e4e4347f4915d41292b5173d196eb9add693be5319fdadc242906178bb6c0286c9b6ca6012746711f58c8c392016b2fdfc09c64f0f6b6ab7b",
            Salt = "3b840e20e9555e9fb031c4ba1f1747ce",
            OpsLimit = 3,
            MemLimit = 7994791,
            OutputLength = 249
          },
          new HashTestObject
          {
            Password =
              "027b6d8e8c8c474e9b69c7d9ed4f9971e8e1ce2f6ba95048414c3970f0f09b70e3b6c5ae05872b3d8678705b7d381829c351a5a9c88c233569b35d6b0b809df44b6451a9c273f1150e2ef8a0b5437eb701e373474cd44b97ef0248ebce2ca0400e1b53f3d86221eca3f18eb45b702b9172440f774a82cbf1f6f525df30a6e293c873cce69bb078ed1f0d31e7f9b8062409f37f19f8550aae",
            Salt = "eb2a3056a09ad2d7d7f975bcd707598f",
            OpsLimit = 4,
            MemLimit = 1397645,
            OutputLength = 152
          },
          new HashTestObject
          {
            Password =
              "4a857e2ee8aa9b6056f2424e84d24a72473378906ee04a46cb05311502d5250b82ad86b83c8f20a23dbb74f6da60b0b6ecffd67134d45946ac8ebfb3064294bc097d43ced68642bfb8bbbdd0f50b30118f5e",
            Salt = "39d82eef32010b8b79cc5ba88ed539fb",
            OpsLimit = 3,
            MemLimit = 1432947,
            OutputLength = 82
          },
          new HashTestObject
          {
            Password =
              "c7b09aec680e7b42fedd7fc792e78b2f6c1bea8f4a884320b648f81e8cf515e8ba9dcfb11d43c4aae114c1734aa69ca82d44998365db9c93744fa28b63fd16000e8261cbbe083e7e2da1e5f696bde0834fe53146d7e0e35e7de9920d041f5a5621aabe02da3e2b09b405b77937efef3197bd5772e41fdb73fb5294478e45208063b5f58e089dbeb6d6342a909c1307b3fff5fe2cf4da56bdae50848f",
            Salt = "039c056d933b475032777edbaffac50f",
            OpsLimit = 3,
            MemLimit = 4886999,
            OutputLength = 156
          },
          new HashTestObject
          {
            Password =
              "a14975c26c088755a8b715ff2528d647cd343987fcf4aa25e7194a8417fb2b4b3f7268da9f3182b4cfb22d138b2749d673a47ecc7525dd15a0a3c66046971784bb63d7eae24cc84f2631712075a10e10a96b0e0ee67c43e01c423cb9c44e5371017e9c496956b632158da3fe12addecb88912e6759bc37f9af2f45af72c5cae3b179ffb676a697de6ebe45cd4c16d4a9d642d29ddc0186a0a48cb6cd62bfc3dd229d313b301560971e740e2cf1f99a9a090a5b283f35475057e96d7064e2e0fc81984591068d55a3b4169f22cccb0745a2689407ea1901a0a766eb99",
            Salt = "3d968b2752b8838431165059319f3ff8",
            OpsLimit = 3,
            MemLimit = 1784128,
            OutputLength = 220
          }
        };

        foreach (var testObject in testObjects)
        {
          Assert.AreEqual(testObject.OutputLength,
            PasswordHash.ArgonHashBinary(Utilities.HexToBinary(testObject.Password),
              Utilities.HexToBinary(testObject.Salt), testObject.OpsLimit, testObject.MemLimit, testObject.OutputLength)
              .Length);

          Assert.AreEqual(testObject.OutputLength,
            PasswordHash.ArgonHashBinary(Utilities.HexToBinary(testObject.Password),
                Utilities.HexToBinary(testObject.Salt), testObject.OpsLimit, testObject.MemLimit, testObject.OutputLength,
                PasswordHash.ArgonAlgorithm.Argon_2ID13).Length);
        }
      }
      catch (OutOfMemoryException e)
      {
        Assert.Inconclusive(e.ToString());
      }
    }

    [Test]
    public void ArgonHashStringVerifyTest()
    {
      const int OUTPUT = 1;
      const int PASS = 0;
      var tests = new List<string[]>
      {
        new[] {"", "$argon2i$v=19$m=2048,t=4,p=1$SWkxaUhpY21ISDcrRnYzSw$Mbg/Eck1kpZir5T9io7C64cpffdTBaORgyriLQFgQj8"},
        new[]
        {
          "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg ",
          "$argon2i$v=19$m=4096,t=3,p=2$X1NhbHQAAAAAAAAAAAAAAA$z/QMiU4lQxGsYNc/+K/bizwsA1P11UG2dj/7+aILJ4I"
        },
        new[]
        {
          "K3S=KyH#)36_?]LxeR8QNKw6X=gFbxai$C%29V*",
          "$argon2i$v=19$m=4096,t=3,p=1$X1NhbHQAAAAAAAAAAAAAAA$fu2Wsecyt+yPnBvSvYN16oP5ozRmkp0ixJ1YL19V3Uo"
        }
      };

      foreach (var test in tests)
      {
        Assert.IsTrue(PasswordHash.ArgonHashStringVerify(test[OUTPUT], test[PASS]));
      }
    }

    /// <summary>Verify that the length of the returned salt is correct.</summary>
    [Test]
    public void ScryptGenerateSaltTest()
    {
      Assert.AreEqual(32, PasswordHash.ScryptGenerateSalt().Length);
    }

    /// <summary>Verify that the length of the returned salt is correct.</summary>
    [Test]
    public void TestGenerateSalt()
    {
#pragma warning disable 618
      Assert.AreEqual(32, PasswordHash.GenerateSalt().Length);
#pragma warning restore 618
    }

    [Test]
    public void ScryptHashStringTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      //See: https://download.libsodium.org/doc/password_hashing/scrypt.html
      // (MEM_LIMIT: It is recommended to allow the function to use at least 16 megabytes.)
      const long OPS_LIMIT = 481326;
      const int MEM_LIMIT = 7256678; //~7.26 MB

      var hash = PasswordHash.ScryptHashString(PASSWORD, OPS_LIMIT, MEM_LIMIT);

      Assert.IsTrue(PasswordHash.ScryptHashStringVerify(hash, PASSWORD));
    }

    [Test]
    public void ScryptHashStringInteractiveTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      var hash = PasswordHash.ScryptHashString(PASSWORD);

      Assert.IsTrue(PasswordHash.ScryptHashStringVerify(hash, PASSWORD));
    }

    [Test]
    public void ScryptHashStringModerateTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
#pragma warning disable 618
      var hash = PasswordHash.ScryptHashString(PASSWORD, PasswordHash.Strength.Moderate);
#pragma warning restore 618

      Assert.IsTrue(PasswordHash.ScryptHashStringVerify(hash, PASSWORD));
    }

    [Test]
    public void ScryptHashStringMediumTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      var hash = PasswordHash.ScryptHashString(PASSWORD, PasswordHash.Strength.Medium);

      Assert.IsTrue(PasswordHash.ScryptHashStringVerify(hash, PASSWORD));
    }

    [Test]
    public void ScryptHashStringMediumSlowTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      var hash = PasswordHash.ScryptHashString(PASSWORD, PasswordHash.Strength.MediumSlow);

      Assert.IsTrue(PasswordHash.ScryptHashStringVerify(hash, PASSWORD));
    }

    [Test]
    public void ScryptHashStringSensitiveTest()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";

      try
      {
        //Could cause OutOfMemoryException
        var hash = PasswordHash.ScryptHashString(PASSWORD, PasswordHash.Strength.Sensitive);

        Assert.IsTrue(PasswordHash.ScryptHashStringVerify(hash, PASSWORD));
      }
      catch (OutOfMemoryException e)
      {
        Assert.Inconclusive(e.ToString());
      }
    }

    /// <summary>
    ///   Derives some secret keys from some test data.
    /// </summary>
    [Test]
    public void HashSalsa208Sha256LongTest()
    {
      //Some of the values are from: https://github.com/jedisct1/libsodium/blob/master/test/default/pwhash_scrypt.c
      var testObjects = new List<HashTestObject>
      {
        new HashTestObject
        {
          Password =
            "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae065577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08da232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f58d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
          Salt = "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2",
          OpsLimit = 481326,
          MemLimit = 7256678,
          OutputLength = 155
        },
        new HashTestObject
        {
          Password =
            "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e00cc2890277f0fd3c622115772f7048adaebed86e",
          Salt = "f1192dd5dc2368b9cd421338b22433455ee0a3699f9379a08b9650ea2c126f0d",
          OpsLimit = 695191,
          MemLimit = 15738350,
          OutputLength = 55
        },
        new HashTestObject
        {
          Password =
            "92263cbf6ac376499f68a4289d3bb59e5a22335eba63a32e6410249155b956b6a3b48d4a44906b18b897127300b375b8f834f1ceffc70880a885f47c33876717e392be57f7da3ae58da4fd1f43daa7e44bb82d3717af4319349c24cd31e46d295856b0441b6b289992a11ced1cc3bf3011604590244a3eb737ff221129215e4e4347f4915d41292b5173d196eb9add693be5319fdadc242906178bb6c0286c9b6ca6012746711f58c8c392016b2fdfc09c64f0f6b6ab7b",
          Salt = "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194",
          OpsLimit = 535778,
          MemLimit = 7849083,
          OutputLength = 250
        },
        new HashTestObject
        {
          Password =
            "027b6d8e8c8c474e9b69c7d9ed4f9971e8e1ce2f6ba95048414c3970f0f09b70e3b6c5ae05872b3d8678705b7d381829c351a5a9c88c233569b35d6b0b809df44b6451a9c273f1150e2ef8a0b5437eb701e373474cd44b97ef0248ebce2ca0400e1b53f3d86221eca3f18eb45b702b9172440f774a82cbf1f6f525df30a6e293c873cce69bb078ed1f0d31e7f9b8062409f37f19f8550aae",
          Salt = "eb2a3056a09ad2d7d7f975bcd707598f24cd32518cde3069f2e403b34bfee8a5",
          OpsLimit = 311757,
          MemLimit = 7994791,
          OutputLength = 249
        },
        new HashTestObject
        {
          Password =
            "1845e375479537e9dd4f4486d5c91ac72775d66605eeb11a787b78a7745f1fd0052d526c67235dbae1b2a4d575a74cb551c8e9096c593a497aee74ba3047d911358ede57bc27c9ea1829824348daaab606217cc931dcb6627787bd6e4e5854f0e8",
          Salt = "3ee91a805aa62cfbe8dce29a2d9a44373a5006f4a4ce24022aca9cecb29d1473",
          OpsLimit = 758010,
          MemLimit = 5432947,
          OutputLength = 190
        },
        new HashTestObject
        {
          Password =
            "c7b09aec680e7b42fedd7fc792e78b2f6c1bea8f4a884320b648f81e8cf515e8ba9dcfb11d43c4aae114c1734aa69ca82d44998365db9c93744fa28b63fd16000e8261cbbe083e7e2da1e5f696bde0834fe53146d7e0e35e7de9920d041f5a5621aabe02da3e2b09b405b77937efef3197bd5772e41fdb73fb5294478e45208063b5f58e089dbeb6d6342a909c1307b3fff5fe2cf4da56bdae50848f",
          Salt = "039c056d933b475032777edbaffac50f143f64c123329ed9cf59e3b65d3f43b6",
          OpsLimit = 233177,
          MemLimit = 13101817,
          OutputLength = 212
        },
        new HashTestObject
        {
          Password =
            "8f3a06e2fd8711350a517bb12e31f3d3423e8dc0bb14aac8240fca0995938d59bb37bd0a7dfc9c9cc0705684b46612e8c8b1d6655fb0f9887562bb9899791a0250d1320f945eda48cdc20c233f40a5bb0a7e3ac5ad7250ce684f68fc0b8c9633bfd75aad116525af7bdcdbbdb4e00ab163fd4df08f243f12557e",
          Salt = "90631f686a8c3dbc0703ffa353bc1fdf35774568ac62406f98a13ed8f47595fd",
          OpsLimit = 234753,
          MemLimit = 4886999,
          OutputLength = 178
        },
        new HashTestObject
        {
          Password = "b540beb016a5366524d4605156493f9874514a5aa58818cd0c6dfffaa9e90205f17b",
          Salt = "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb",
          OpsLimit = 78652,
          MemLimit = 6631659,
          OutputLength = 231
        },
        new HashTestObject
        {
          Password =
            "a14975c26c088755a8b715ff2528d647cd343987fcf4aa25e7194a8417fb2b4b3f7268da9f3182b4cfb22d138b2749d673a47ecc7525dd15a0a3c66046971784bb63d7eae24cc84f2631712075a10e10a96b0e0ee67c43e01c423cb9c44e5371017e9c496956b632158da3fe12addecb88912e6759bc37f9af2f45af72c5cae3b179ffb676a697de6ebe45cd4c16d4a9d642d29ddc0186a0a48cb6cd62bfc3dd229d313b301560971e740e2cf1f99a9a090a5b283f35475057e96d7064e2e0fc81984591068d55a3b4169f22cccb0745a2689407ea1901a0a766eb99",
          Salt = "3d968b2752b8838431165059319f3ff8910b7b8ecb54ea01d3f54769e9d98daf",
          OpsLimit = 717248,
          MemLimit = 10784179,
          OutputLength = 167
        }
      };

      foreach (var testObject in testObjects)
      {
        Assert.AreEqual(testObject.OutputLength,
          PasswordHash.ScryptHashBinary(Utilities.HexToBinary(testObject.Password),
            Utilities.HexToBinary(testObject.Salt), testObject.OpsLimit, testObject.MemLimit, testObject.OutputLength)
            .Length);
      }
    }

    /// <summary>
    ///   Tests if a output size that's too small will trigger an exception.
    /// </summary>
    [Test]
    public void HashSalsa208Sha256TooShort()
    {
      const string PASSWORD =
        "4a857e2ee8aa9b6056f2424e84d24a72473378906ee04a46cb05311502d5250b82ad86b83c8f20a23dbb74f6da60b0b6ecffd67134d45946ac8ebfb3064294bc097d43ced68642bfb8bbbdd0f50b30118f5e";
      const string SALT = "39d82eef32010b8b79cc5ba88ed539fbaba741100f2edbeca7cc171ffeabf258";
      var password = Utilities.HexToBinary(PASSWORD);
      var salt = Utilities.HexToBinary(SALT);
      Assert.Throws<ArgumentOutOfRangeException>(
        () => PasswordHash.ScryptHashBinary(password, salt, 643464, 1397645, 5));
    }

    /// <summary>
    ///   Derives a 32 byte long secret key from a password and a salt.
    /// </summary>
    [Test]
    public void ScryptHashBinary32ByteTest()
    {
      const string PASSWORD =
        "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e00cc2890277f0fd3c622115772f7048adaebed86e";
      const string SALT = "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb";
      const long OUTPUT_LENGTH = 32;
      var hash1 = PasswordHash.ScryptHashBinary(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT),
        PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
      var hash2 = PasswordHash.ScryptHashBinary(Utilities.HexToBinary(PASSWORD), Utilities.HexToBinary(SALT),
        PasswordHash.Strength.Interactive, OUTPUT_LENGTH);

      Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
      Assert.AreEqual(hash1, hash2);
    }

    /// <summary>
    ///   Derives a 32 byte long secret key from a password and a salt.
    /// </summary>
    [Test]
    public void ScryptHashBinary32Test()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
      const long OUTPUT_LENGTH = 32;
      var hash1 = PasswordHash.ScryptHashBinary(PASSWORD, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
      var hash2 = PasswordHash.ScryptHashBinary(PASSWORD, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);

      Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
      Assert.AreEqual(hash1, hash2);
    }

    /// <summary>
    ///   Derives a 128 byte long secret key from a password and a salt.
    /// </summary>
    [Test]
    public void ScryptHashBinary128Test()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
      const long OUTPUT_LENGTH = 128;
      var hash1 = PasswordHash.ScryptHashBinary(PASSWORD, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
      var hash2 = PasswordHash.ScryptHashBinary(PASSWORD, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);

      Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
      Assert.AreEqual(hash1, hash2);
    }

    /// <summary>
    ///   Derives a 512 byte long secret key from a password and a salt.
    /// </summary>
    [Test]
    public void ScryptHashBinary512Test()
    {
      const string PASSWORD = "gkahjfkjewrykjKJHKJHKJbhuiqyr  8923fhsjfkajwehkjg";
      const string SALT = "qa~t](84z<1t<1oz:ik.@IRNyhG=8q(o";
      const long OUTPUT_LENGTH = 512;
      var hash1 = PasswordHash.ScryptHashBinary(PASSWORD, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);
      var hash2 = PasswordHash.ScryptHashBinary(PASSWORD, SALT, PasswordHash.Strength.Interactive, OUTPUT_LENGTH);

      Assert.AreEqual(OUTPUT_LENGTH, hash1.Length);
      Assert.AreEqual(OUTPUT_LENGTH, hash2.Length);
      Assert.AreEqual(hash1, hash2);
    }

    [Test]
    public void ScryptHashStringVerifyTest()
    {
      const int OUTPUT = 1;
      const int PASS = 0;
      var tests = new List<string[]>
      {
        new[]
        {
          "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg nrDFal+Jxl3,2`#^tFSu%v_+7iYse8-cCkNf!tD=KrW)",
          "$7$B6....1....75gBMAGwfFWZqBdyF3WdTQnWdUsuTiWjG1fF9c1jiSD$tc8RoB3.Em3/zNgMLWo2u00oGIoTyJv4fl3Fl8Tix72"
        },
        new[]
        {
          "bl72h6#y<':MFRZ>B IA1=NRkCKS%W8`1I.2uQxJN0g)N N aTt^4K!Iw5r H6;crDsv^a55j9tsk'/GqweZn;cdk6+F_St6:#*=?ZCD_lw>.",
          "$7$A6....3....Iahc6qM0.UQJHVgE4h9oa1/4OWlWLm9CCtfguvz6bQD$QnXCo3M7nIqtry2WKsUZ5gQ.mY0wAlJu.WUhtE8vF66"
        },
        new[]
        {
          "Py >e.5b+tLo@rL`dC2k@eJ&4eVl!W=JJ4+k&mAt@gt',FS1JjqKW3aq21:]^kna`mde7kVkN5NrpKUptu)@4*b&?BE_sJMG1=&@`3GBCV]Wg7xwgo7x3El",
          "$7$96..../....f6bEusKt79kK4wdYN0ki2nw4bJQ7P3rN6k3BSigsK/D$Dsvuw7vXj5xijmrb/NOhdgoyK/OiSIYv88cEtl9Cik7"
        },
        new[]
        {
          "2vj;Um]FKOL27oam(:Uo8+UmSTvb1FD*h?jk_,S=;RDgF-$Fjk?]9yvfxe@fN^!NN(Cuml?+2Raa",
          "$7$86....I....7XwIxLtCx4VphmFeUa6OGuGJrFaIaYzDiLNu/tyUPhD$U3q5GCEqCWxMwh.YQHDJrlg7FIZgViv9pcXE3h1vg61"
        },
        new[]
        {
          "CT=[9uUoGav,J`kU+348tA50ue#sL:ABZ3QgF+r[#vh:tTOiL>s8tv%,Jeo]jH/_4^i(*jD-_ku[9Ko[=86 06V",
          "$7$A6....2....R3.bjH6YS9wz9z8Jsj.3weGQ3J80ZZElGw2oVux1TP6$i5u6lFzXDHaIgYEICinLD6WNaovbiXP8SnLrDRdKgA9"
        },
        new[]
        {
          "J#wNn`hDgOpTHNI.w^1a70%f,.9V_m038H_JIJQln`vdWnn/rmILR?9H5g(+`;@H(2VosN9Fgk[WEjaBr'yB9Q19-imNa04[Mk5kvGcSn-TV",
          "$7$B6....1....Dj1y.4mF1J9XmT/6IDskYdCLaPFJTq9xcCwXQ1DpT92$92/hYfZLRq1nTLyIz.uc/dC6wLqwnsoqpkadrCXusm6"
        },
        new[]
        {
          "j4BS38Asa;p)[K+9TY!3YDj<LK-`nLVXQw9%*QfM",
          "$7$B6....1....5Ods8mojVwXJq4AywF/uI9BdMSiJ/zT8hQP/4cB68VC$nk4ExHNXJ802froj51/1wJTrSZvTIyyK7PecOxRRaz0"
        },
        new[]
        {
          "M.R>Qw+!qJb]>pP :_.9`dxM9k [eR7Y!yL-3)sNs[R,j_/^ TH=5ny'15>6UXWcQW^6D%XCsO[vN[%ReA-`tV1vW(Nt*0KVK#]45P_A",
          "$7$B6....1....D/eyk8N5y6Z8YVQEsw521cTx.9zzLuK7YDs1KMMh.o4$alfW8ZbsUWnXc.vqon2zoljVk24Tt1.IsCuo2KurvS2"
        },
        new[]
        {
          "K3S=KyH#)36_?]LxeR8QNKw6X=gFb'ai$C%29V* tyh^Wo$TN-#Q4qkmtTCf0LLb.^E$0uykkP",
          "$7$B6....1....CuBuU97xgAage8whp/JNKobo0TFbsORGVbfcQIefyP8$aqalP.XofGViB8EPLONqHma8vs1xc9uTIMYh9CgE.S8"
        },
        new[]
        {
          "Y0!?iQa9M%5ekffW(`",
          "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5"
        }
      };

      foreach (var test in tests)
      {
        Assert.IsTrue(PasswordHash.ScryptHashStringVerify(test[OUTPUT], test[PASS]));
      }
    }
  }
}