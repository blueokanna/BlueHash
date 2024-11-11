# BlueHash 算法文档 - (English Version)[https://github.com/blueokanna/BlueHash/blob/main/README.md]

## 概述

**BlueHash** 算法是一种自定义的加密哈希函数，旨在生成具有不同位数（128、256 和 512 位）且安全的哈希值。它利用多个回合的转换，包括状态更新、置换函数和常量生成，这些都有助于最终哈希输出的独特性和安全性。

本文档提供了该算法核心组件的解释，包括状态大小、回合次数、常量生成和状态更新转换。文中还提供了描述每一步过程的数学公式。

## 关键组件

### 1. 状态大小和摘要长度

**BlueHash** 算法使用固定的状态大小，并根据所需的输出大小选择不同的摘要长度。

- **状态大小**：25 个 64 位字（即 \( STATE\_SIZE = 25 \)）。
- **摘要长度**：根据摘要大小，可能是 128、256 或 512 位。

每个摘要大小的回合数和输出长度如下：

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
- \( r \) 是回合号。
- `round_factor` 是回合号的一个函数。
- `extra_prime` 是一个较大的质数常量。
- `noise` 是由输入数据和回合号生成的噪声。
- `hash_length` 是最终摘要的长度。

这样确保了每个回合都有一个独特的常量，增强了哈希过程的安全性和随机性。

### 3. 状态更新和置换

`update` 和 `permute` 函数实现了算法的核心转换逻辑。每个回合都涉及使用当前回合常量更新状态，并应用各种按位操作来实现扩散和混淆。

状态 \( \text{state}[i] \) 在回合 \( r \) 时的更新公式如下：

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

## 总结

**BlueHash** 算法是一种自定义的加密哈希函数，利用多个回合的复杂转换生成不同长度的安全哈希。它使用固定的状态大小、基于回合的转换和常量生成来确保最终输出的独特性和安全性。
