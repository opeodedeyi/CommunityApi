const express = require('express');
const auth = require('../middleware/auth');
const isEmailConfirmed = require('../middleware/isEmailConfirmed');
const Group = require('../models/group');

const router = new express.Router();


/**
 * @route POST /group
 * @desc Create a new social club (group)
 * @access Private (Authenticated and email confirmed users only)
 * 
 * This route allows a verified user (authenticated and with a confirmed email address) 
 * to create a new social club. The authenticated user's ID is set as the owner of the club.
 */
router.post('/group', auth, isEmailConfirmed, async (req, res) => {
    try {
        // Create a new group with the provided data and set the owner to the authenticated user
        const group = new Group({
            ...req.body,
            owner: req.user._id,
        });

        // Save the group to the database
        await group.save();

        // Send a 201 Created response with the created group
        res.status(201).send(group);
    } catch (e) {
        // Send a 400 Bad Request response if an error occurs
        res.status(400).send(e);
    }
});


/**
 * Route to join a group.
 * The user must be authenticated and have a confirmed email address to join a group.
 *
 * @route POST /group/:id/join
 * @param {string} id - The ID of the group to join.
 * @requires {function} auth - The authentication middleware.
 * @requires {function} isEmailConfirmed - The middleware to check if the user's email is confirmed.
 */
router.post('/group/:id/join', auth, isEmailConfirmed, async (req, res) => {
    try {
        // Get the group ID from the request parameters and find the group
        const groupId = req.params.id;
        const group = await Group.findById(groupId);

        if (!group) {
            return res.status(404).send({ error: 'Group not found' });
        }

        const userId = req.user._id;

        // Check if the user is already a member or has a pending request
        const isMember = group.members.some((memberId) => memberId.equals(userId));
        const hasRequest = group.requests.some((requestId) => requestId.equals(userId));

        if (isMember) {
            return res.status(400).send({ error: 'You are already a member of this group' });
        }

        if (hasRequest) {
            return res.status(400).send({ error: 'You already have a pending request to join this group' });
        }

        if (group.permissionRequired) {
            // Add the user to the requests list
            group.requests.push(userId);
        } else {
            // Add the user to the members list
            group.members.push(userId);
        }

        // Save the updated group
        await group.save();

        res.status(200).send(group);
    } catch (e) {
        res.status(500).send({ error: 'Server error' });
    }
});


/**
 * Route for a member to leave a group.
 * The user must be authenticated and have their email confirmed.
 * 
 * @route POST /group/:id/leave
 * @param {string} id - The ID of the group to leave.
 * @requires {function} auth - The authentication middleware.
 * @requires {function} isEmailConfirmed - The middleware to check if the user's email is confirmed.
 */
router.post('/group/:id/leave', auth, isEmailConfirmed, async (req, res) => {
    try {
        // Get the group ID from the request parameters
        const groupId = req.params.id;

        // Find the group by its ID
        const group = await Group.findById(groupId);

        // If the group is not found, send a 404 Not Found response
        if (!group) {
            return res.status(404).send({ error: 'Group not found' });
        }

        const userId = req.user._id;

        // Check if the user is a member of the group
        const isMember = group.members.some((memberId) => memberId.equals(userId));

        // If the user is not a member, send a 400 Bad Request response
        if (!isMember) {
            return res.status(400).send({ error: 'You are not a member of this group' });
        }

        // Remove the user from the members list
        group.members = group.members.filter((memberId) => !memberId.equals(userId));

        // Check if the user is a moderator and remove them from the moderators list if necessary
        const isModerator = group.moderators.some((moderatorId) => moderatorId.equals(userId));
        if (isModerator) {
            group.moderators = group.moderators.filter((moderatorId) => !moderatorId.equals(userId));
        }

        // Save the updated group
        await group.save();

        // Send a 200 OK response with the updated group
        res.status(200).send(group);
    } catch (e) {
        // Send a 500 Internal Server Error response if an error occurs
        res.status(500).send({ error: 'Server error' });
    }
});


module.exports = router;
