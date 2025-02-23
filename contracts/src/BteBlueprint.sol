// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

import "tnt-core/BlueprintServiceManagerBase.sol";

/**
 * @title BteBlueprint
 * @dev This contract is an example of a service blueprint that provides a single service.
 * @dev For all supported hooks, check the `BlueprintServiceManagerBase` contract.
 */
contract BteBlueprint is BlueprintServiceManagerBase {
    mapping(uint64 => mapping(uint64 => bytes)) public dataStore;
    uint64 public currentIndex = 1;

    // Function to store data at the current index, callable only by the creator
    function storeData(uint64 serviceId, bytes memory data) public {
        dataStore[serviceId][currentIndex++] = data;
    }

    function getData(uint64 serviceId, uint64 index) public view returns (bytes memory) {
        return dataStore[serviceId][index];
    }
}
