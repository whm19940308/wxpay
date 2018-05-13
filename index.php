<?php

include './Wxpay.class.php';


$openid = ''; // 调用【网页授权获取用户信息】接口获取到用户在该公众号下的Openid
$totalFee = 0.01;   // 收款总费用 单位元
$outTradeNo = 'SH'.date('YmdHis').mt_rand(100000,999999); // 唯一的订单号
$orderName = '订单名称'; // 订单名称
$notifyUrl = ''; // 异步请求url
$timestamp = (string)time(); // 当前时间戳，需要转成string类型，不然微信支付不支持

$pay_obj = $this->createJsBizPackage($openid, $totalFee, $outTradeNo, $orderName, $notifyUrl, $timestamp);

echo '<pre>';
var_dump($pay_obj);