// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureStorage {
    address public creator;
    mapping(uint64 => bytes) public dataStore;
    uint64 public currentIndex = 1;

    modifier onlyCreator() {
        require(
            msg.sender == creator,
            "Only the creator can call this function"
        );
        _;
    }

    constructor() {
        creator = msg.sender; // Set the deployer as the creator
    }

    // Function to store data at the current index, callable only by the creator
    function storeData(bytes memory data) public onlyCreator {
        dataStore[currentIndex] = data;
        currentIndex++; // Increment the index for the next entry
    }

    function getData(uint64 index) public view returns (bytes memory) {
        return dataStore[index];
    }
}
