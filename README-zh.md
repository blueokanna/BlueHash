# BlueHash 算法文档 - [English Version](https://github.com/blueokanna/BlueHash/blob/main/README.md)

## 概述

**BlueHash** 算法是一种自定义的加密哈希函数，旨在生成具有不同位数（128、256 和 512 位）且安全的哈希值。它利用多个回合的转换，包括状态更新、置换函数和常量生成，这些都有助于最终哈希输出的独特性和安全性。

本文档提供了该算法核心组件的解释，包括状态大小、回合次数、常量生成和状态更新转换。文中还提供了描述每一步过程的数学公式。

## 使用示例

```
use BlueHash::BlueHash;     //需要在 cargo.toml 调用BlueHash 库

fn main() {
    let data = b"Hello World";
    let key: u64 = 0x1234567890abcdef;

    let mut hash_128 = BlueHash::new(DigestSize::Bit256,key);
    hash_128.update(data);
    let result_128 = hash_128.finalize();
    println!("128-bit hash: {:?}", result_128);

    let mut hash_256 = BlueHash::new(DigestSize::Bit256,key);
    hash_256.update(data);
    let result_256 = hash_256.finalize();
    println!("256-bit hash: {:?}", result_256);

    let mut hash_512 = BlueHash::new(DigestSize::Bit512,key);
    hash_512.update(data);
    let result_512 = hash_512.finalize();
    println!("512-bit hash: {:?}", result_512);
}
```

## 关键组件

### 1. 状态大小和摘要长度

**BlueHash** 算法使用固定的状态大小，并根据所需的输出大小选择不同的摘要长度。

- **状态大小**：25 个 64 位字（即 \( STATE\_SIZE = 25 \)）。
- **摘要长度**：根据摘要大小，可能是 128、256 或 512 位。

每个摘要大小的轮次数和输出长度如下：

$$
R(d) = 
\begin{cases} 
56, & \text{如果 } d = 128 \text{ 位} \\
64, & \text{如果 } d = 256 \text{ 位} \\
80, & \text{如果 } d = 512 \text{ 位}
\end{cases}
$$

$$
L(d) = 
\begin{cases} 
16, & \text{如果 } d = 128 \text{ 位} \\
32, & \text{如果 } d = 256 \text{ 位} \\
64, & \text{如果 } d = 512 \text{ 位}
\end{cases}
$$

### 2. 常量生成

`generate_constants` 函数为每个哈希转换回合生成一个独特的常量。常量是基于多个因素生成的，包括回合号、输入数据和预定义常量。

常量的生成公式如下：

$$
\text{constant} = \left( p \ll (r \mod 64) \right) \times \left( r + \text{round factor} \right) \ll 32 + \left( r + \text{round factor} \right) \gg 16 + \text{extra prime} \ll (r \mod 32) + \text{noise} \ll 8 + \text{hash length}
$$

其中：
- \( p \) 是一个固定的质数常量。
- \( r \) 是轮次。
- `round_factor` 是回合号的一个函数。
- `extra_prime` 是一个较大的质数常量。
- `noise` 是由输入数据和回合号生成的噪声。
- `hash_length` 是最终摘要的长度。

这样确保了每个回合都有一个独特的常量，增强了哈希过程的安全性和随机性。

### 3. 状态更新和置换

`update` 和 `permute` 函数实现了算法的核心转换逻辑。每个回合都涉及使用当前回合常量更新状态，并应用各种按位操作来实现扩散和混淆。

状态 `state[i]` 在轮次 `r` 时的更新公式如下：

$$
\text{state}[i] = \left( \text{state}[i] \ll 29 \right) + \text{constant} + \text{local\ vars}[2] \oplus \left( \text{local\ vars}[0] \land \text{local\ vars}[1] \right) \oplus \left( \text{local\ vars}[3] \gg 17 \right) \oplus \left( \text{constant} \ll 23 \right)
$$

其中：
- `state[i]` 是状态数组的第 \( i \) 个元素。
- `local vars` 是从邻近状态值派生出的变量。
- `<<` 和 `>>` 分别表示按位左移和右移。
- `⊕` 表示按位异或操作。
- `&` 表示按位与操作。

这种转换确保了每个回合的哈希函数引入非线性混合，有助于实现扩散（小的输入变化导致大的输出变化）和混淆（输出与输入之间没有明显的关系）。

### 4. 最终哈希生成

最终的哈希通过从所有回合转换完成后提取内部状态的位来生成。最终的摘要是通过从状态中提取 64 位的块并将其转换为字节来生成的。

生成最终摘要的公式为：

$$
\text{digest}[j] = \text{state}\left[\frac{j}{8} \mod \text{STATE\ SIZE}\right]
$$

其中：
- `digest[j]` 是最终哈希的第 \( j \) 个字节。
- `state[j / 8 \mod STATE_SIZE]` 表示从状态数组中获取的值。

结果字节被连接起来，形成最终的哈希值，这是 `finalize` 函数的输出。

### 5. 正确性与安全性

**BlueHash** 算法的安全性基于以下原则：

- **唯一性**：每个回合使用的常量都取决于回合号、输入数据和一系列质数。这确保了没有两个回合产生相同的转换。
- **抗碰撞性**：每回合的非线性转换和状态变量的混合使得计算上很难找到两个不同的输入产生相同的哈希输出。
- **扩散与混淆**：状态更新函数中使用的按位操作（异或、与、移位）确保了输入的小变化会导致哈希值的大幅变化，这是一个好的加密哈希函数的核心。

遵循这些原则，**BlueHash** 被设计为一种强大的加密哈希函数，能够抵抗如碰撞查找和预映像攻击等攻击。

# 与 SHA-3 (NIST) 比较
| **1500 样本点** | **SHA3 256** | **SHA3 512** | **BlueHash 128** | **BlueHash 256** | **BlueHash 512** |
|--------------|--------------|--------------|------------------|------------------|------------------|
| Slope        | 334.04 ns	   | 334.41 ns	   | 14.788 µs        | 17.032 µs        | 21.248 µs	       |
| R^2          | 0.7966978	   | 0.7135882    | 0.4950626        | 0.7290226        | 0.6919036        |
| Mean         | 334.45 ns	   | 336.50 ns	   | 14.857 µs        | 17.038 µs	       | 21.270 µs	       |
| std. Dev     | 19.989 ns	   | 14.845 ns	   | 355.87 ns        | 314.64 ns	       | 497.63 ns	       |
| Median       | 333.74 ns	   | 334.67 ns	   | 14.816 µs        | 17.024 µs	       | 21.207 µs	       |
| MAD          | 3.5463 ns	   | 2.8191 ns	   | 178.17 ns        | 205.76 ns	       | 134.15 ns	   

## BlueHash 和 SHA3 的性能基本测试

### **BlueHash-128 (1500 个样本点)**
![BlueHash-128](https://raw.githubusercontent.com/blueokanna/BlueHash/refs/heads/main/compare_result/BlueHash-128.png)

### **BlueHash-256 (1500 个样本点)**
![BlueHash-256](https://raw.githubusercontent.com/blueokanna/BlueHash/refs/heads/main/compare_result/BlueHash-256.png)

### **BlueHash-512 (1500 个样本点)**
![BlueHash-512](https://raw.githubusercontent.com/blueokanna/BlueHash/refs/heads/main/compare_result/BlueHash-512.png)

### **BlueHash Differential Attack (1500 个样本点，1000 万次尝试攻击)**
![Attack](https://raw.githubusercontent.com/blueokanna/BlueHash/refs/heads/main/compare_result/BlueHash_bench.png)


### **SHA3-256 (500 个样本点)**
![SHA3-256](https://raw.githubusercontent.com/blueokanna/BlueHash/refs/heads/main/compare_result/SHA3-256.png)

### **SHA3-512 (500 个样本点)**
![SHA3-512](https://raw.githubusercontent.com/blueokanna/BlueHash/refs/heads/main/compare_result/SHA3-512.png)


## 什么是 **BlueHash** 算法的优缺点？

### 与**SHA3-256**相比，**BlueHash**算法有以下优点：

1. **抗量子攻击**： 
通过 LWE 噪声和恒定生成机制，可以更好地抵御量子攻击。

2. **更高的随机性和复杂性**： 
利用动态生成常数，增加哈希算法的不可预测性。这增加了复杂性，并使算法更能抵御差分攻击。

3. **更强的状态更新和替换**： 
通过更多样化的比特运算和混合运算，提高了对传统攻击和量子攻击的抵御能力。

4. **增强的噪声生成机制**： 
添加 LWE 噪声不仅能提高安全性，还能增强防御能力，尤其是针对量子计算的防御能力。

5. **灵活性**： 
可根据不同的哈希长度灵活调整轮数和其他参数，在确保安全的同时优化性能。

<br>

### BlueHash 的潜在局限性:

1. **较高的性能开销**： 
多轮复杂运算和 LWE 噪声生成会增加计算开销，可能会影响大数据处理的效率。

2. **更高的内存消耗**： 
更多的本地变量和状态存储要求可能会导致低内存环境下的性能瓶颈。

3. **缺乏标准化和审计**： 
与 SHA3-256 相比，**BlueHash** 缺乏广泛的安全审计。

----
> **BlueHash** 算法是一种自定义的加密哈希函数，利用多个回合的复杂转换生成不同长度的安全哈希。它使用固定的状态大小、基于回合的转换和常量生成来确保最终输出的独特性和安全性。
----

## 贡献
| ![Tether](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/tether.png "Tether (USDT)") **USDT** : Arbitrum One Network: **0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed** | ![USD Coin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/usd-coin.png "USD Coin (USDC)") **USDC**: Arbitrum One Network: **0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed** | ![Dash Coin](https://raw.githubusercontent.com/ErikThiart/cryptocurrency-icons/master/16/dash.png "Dash Coin (Dash)") **Dash**: Dash Network: **XuJwtHWdsYzfLawymR3B3nDdS2W8dHnxyR** |
|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|

| ![0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed](https://github.com/user-attachments/assets/608c5e0d-edfc-4dee-be6f-63d40b53a65f) | ![0x4051d34Af2025A33aFD5EacCA7A90046f7a64Bed (1)](https://github.com/user-attachments/assets/87205826-1f76-4724-9734-3ecbfbfb729f) | ![XuJwtHWdsYzfLawymR3B3nDdS2W8dHnxyR](https://github.com/user-attachments/assets/71915604-cc14-426f-a8b9-9b7f023da084) |
|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
